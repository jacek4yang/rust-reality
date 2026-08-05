use std::{
    error::Error,
    fmt, io,
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{OwnedSemaphorePermit, Semaphore},
};

use crate::{config::RelayPolicy, runtime::FdBudget};

#[cfg(target_os = "linux")]
use crate::runtime::{FdPermit, UNITS_SPLICE_DIRECTION, UNITS_SPLICE_RELAY};

/// Maximum io_uring driver shards, and therefore ring descriptors, per process.
///
/// Exposed so the startup descriptor plan can reserve the ring descriptors
/// before deriving the dynamic budget rather than discovering them later.
pub const MAX_URING_SHARDS: u16 = 4;

/// Submission-queue depth per io_uring driver shard.
pub const URING_QUEUE_DEPTH: u16 = 256;

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
                policy.buffer_bytes,
                fd_budget.clone(),
            )
        });
        let report = BackendReport {
            buffered: BackendCapability::available(),
            splice: splice_capability(policy),
            io_uring: probe_io_uring(policy),
            sockhash: probe_sockhash(policy),
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
    /// another backend.
    pub async fn relay_direction(
        &self,
        mut source: OwnedReadHalf,
        mut destination: OwnedWriteHalf,
        direction: RelayDirection,
        request: BackendRequest,
    ) -> io::Result<DirectionalRelayOutcome> {
        let order = directional_selection_order(request);
        let mut last_decline = BackendDeclineReason::Disabled;
        for backend in order {
            let ledger = TransferLedger::new();
            let started = Instant::now();
            let run = self
                .run_direction_backend(
                    *backend,
                    &mut source,
                    &mut destination,
                    direction,
                    &ledger,
                    started,
                )
                .await?;
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
        direction: RelayDirection,
        ledger: &TransferLedger,
        started: Instant,
    ) -> io::Result<BackendRun> {
        match backend {
            RelayBackend::Buffered => {
                self.buffers
                    .relay_direction(source, destination, direction, ledger)
                    .await?;
                Ok(ledger.complete(RelayBackend::Buffered, started.elapsed()))
            }
            RelayBackend::Splice => {
                self.run_splice_direction(source, destination, direction, ledger, started)
                    .await
            }
            // The io_uring and sockhash backends are pair-only. They never
            // appear in the directional selection order, so this arm only
            // exists to keep the match exhaustive; nothing is recorded.
            RelayBackend::IoUring | RelayBackend::Sockhash => {
                ledger.decline(BackendDeclineReason::Disabled)
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn run_splice_direction(
        &self,
        source: &mut OwnedReadHalf,
        destination: &mut OwnedWriteHalf,
        direction: RelayDirection,
        ledger: &TransferLedger,
        started: Instant,
    ) -> io::Result<BackendRun> {
        let Some(splice) = &self.splice else {
            return ledger.decline(BackendDeclineReason::Disabled);
        };
        match splice
            .try_relay_direction(source, destination, direction, ledger)
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
        _direction: RelayDirection,
        ledger: &TransferLedger,
        _started: Instant,
    ) -> io::Result<BackendRun> {
        ledger.decline(BackendDeclineReason::UnsupportedOperatingSystem)
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
                .await?;
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
                self.buffers.relay(inbound, outbound, ledger).await?;
                Ok(ledger.complete(RelayBackend::Buffered, started.elapsed()))
            }
            RelayBackend::Splice => self.run_splice(inbound, outbound, ledger, started).await,
            RelayBackend::IoUring | RelayBackend::Sockhash => {
                let reason = self
                    .report
                    .capability(backend)
                    .decline_reason
                    .unwrap_or(BackendDeclineReason::Disabled);
                let _unused = context;
                ledger.decline(reason)
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
    ) -> io::Result<BackendRun> {
        let Some(splice) = &self.splice else {
            return ledger.decline(BackendDeclineReason::Disabled);
        };
        match splice.try_relay(inbound, outbound, ledger).await? {
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

/// Returns the backend order for one request.
fn selection_order(request: BackendRequest) -> &'static [RelayBackend] {
    match request {
        BackendRequest::Automatic => RelayBackend::automatic_preference(),
        BackendRequest::Explicit(RelayBackend::Buffered) => &[RelayBackend::Buffered],
        BackendRequest::Explicit(RelayBackend::Splice) => {
            &[RelayBackend::Splice, RelayBackend::Buffered]
        }
        BackendRequest::Explicit(RelayBackend::IoUring) => &[
            RelayBackend::IoUring,
            RelayBackend::Splice,
            RelayBackend::Buffered,
        ],
        BackendRequest::Explicit(RelayBackend::Sockhash) => &[
            RelayBackend::Sockhash,
            RelayBackend::Splice,
            RelayBackend::Buffered,
        ],
    }
}

/// Returns the backend order for one single-direction request.
///
/// The io_uring and sockhash backends are pair-only — they must duplicate or
/// register both complete sockets — so an explicit request for either of them
/// on a single direction means splice-then-buffered, and no decline is
/// recorded for the pair-only backend itself.
fn directional_selection_order(request: BackendRequest) -> &'static [RelayBackend] {
    match request {
        BackendRequest::Automatic
        | BackendRequest::Explicit(RelayBackend::Splice)
        | BackendRequest::Explicit(RelayBackend::IoUring)
        | BackendRequest::Explicit(RelayBackend::Sockhash) => {
            &[RelayBackend::Splice, RelayBackend::Buffered]
        }
        BackendRequest::Explicit(RelayBackend::Buffered) => &[RelayBackend::Buffered],
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

/// Probes io_uring on the running kernel rather than assuming availability.
#[cfg(target_os = "linux")]
fn probe_io_uring(policy: &RelayPolicy) -> BackendCapability {
    if !policy.io_uring {
        return BackendCapability::declined(false, BackendDeclineReason::Disabled);
    }
    capability_from(true, rr_linux::uring::probe())
}

#[cfg(not(target_os = "linux"))]
fn probe_io_uring(policy: &RelayPolicy) -> BackendCapability {
    BackendCapability::declined(
        policy.io_uring,
        BackendDeclineReason::UnsupportedOperatingSystem,
    )
}

/// Probes sockhash on the running kernel, LSM and capability set.
#[cfg(target_os = "linux")]
fn probe_sockhash(policy: &RelayPolicy) -> BackendCapability {
    if !policy.sockhash {
        return BackendCapability::declined(false, BackendDeclineReason::Disabled);
    }
    let Ok(budget) = kernel_budget(policy, policy.max_sockhash_relays) else {
        return BackendCapability::declined(true, BackendDeclineReason::ResourceLimit);
    };
    capability_from(true, rr_linux::sockhash::probe(budget))
}

#[cfg(not(target_os = "linux"))]
fn probe_sockhash(policy: &RelayPolicy) -> BackendCapability {
    BackendCapability::declined(
        policy.sockhash,
        BackendDeclineReason::UnsupportedOperatingSystem,
    )
}

/// Builds the kernel budget from validated relay policy.
#[cfg(target_os = "linux")]
fn kernel_budget(policy: &RelayPolicy, max_relays: u32) -> Result<rr_linux::Budget, ()> {
    let buffer_bytes = u32::try_from(policy.buffer_bytes).map_err(|_| ())?;
    let budget = rr_linux::Budget {
        max_relays,
        buffer_bytes,
        max_shards: 4,
        queue_depth: 256,
    };
    budget.validate().map_err(|_| ())?;
    Ok(budget)
}

/// Maps a probed kernel report into the protocol crate's fixed vocabulary.
///
/// The mapping is total: every `rr-linux` reason has exactly one counterpart, so
/// no probe result can ever be reported as an unexplained failure.
#[cfg(target_os = "linux")]
fn capability_from(enabled: bool, report: rr_linux::ProbeReport) -> BackendCapability {
    match report.overall().reason() {
        None => BackendCapability::available(),
        Some(reason) => BackendCapability::declined(enabled, map_reason(reason)),
    }
}

#[cfg(target_os = "linux")]
const fn map_reason(reason: rr_linux::DeclineReason) -> BackendDeclineReason {
    use rr_linux::DeclineReason as Kernel;
    match reason {
        Kernel::Disabled => BackendDeclineReason::Disabled,
        Kernel::UnsupportedOperatingSystem => BackendDeclineReason::UnsupportedOperatingSystem,
        Kernel::UnsupportedKernel => BackendDeclineReason::UnsupportedKernel,
        Kernel::MissingOperation => BackendDeclineReason::MissingOperation,
        Kernel::MissingCapability => BackendDeclineReason::MissingCapability,
        Kernel::BlockedBySeccomp => BackendDeclineReason::BlockedBySeccomp,
        Kernel::BlockedByLsm => BackendDeclineReason::BlockedByLsm,
        Kernel::VerifierRejected => BackendDeclineReason::VerifierRejected,
        Kernel::ResourceLimit => BackendDeclineReason::ResourceLimit,
        Kernel::QueueUnavailable => BackendDeclineReason::QueueUnavailable,
        Kernel::MapUnavailable => BackendDeclineReason::MapUnavailable,
        Kernel::UnsafeToArm => BackendDeclineReason::UnsafeToArm,
        Kernel::ExistingQueuedBytes => BackendDeclineReason::ExistingQueuedBytes,
        Kernel::InitializationFailure => BackendDeclineReason::InitializationFailure,
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
        );
        let downlink = copy_direction(
            outbound_reader,
            inbound_writer,
            outbound_buffer,
            ledger,
            false,
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
    ) -> io::Result<()> {
        let mut lease = self.acquire_single().await?;
        let buffer = lease.buffer_mut()?;
        copy_direction(
            source,
            destination,
            buffer,
            ledger,
            direction.is_inbound_to_outbound(),
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
async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    buffer: &mut [u8],
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let read = reader.read(buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let payload = buffer
            .get(..read)
            .ok_or_else(|| io::Error::other("TCP relay read exceeded its buffer"))?;
        writer.write_all(payload).await?;
        record(ledger, inbound_to_outbound, read)?;
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

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct SplicePool {
    permits: Arc<Semaphore>,
    chunk_bytes: usize,
    fd_budget: FdBudget,
}

#[cfg(target_os = "linux")]
impl SplicePool {
    fn new(max_relays: u32, chunk_bytes: usize, fd_budget: FdBudget) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(
                usize::try_from(max_relays).map_or(usize::MAX, |value| value),
            )),
            chunk_bytes,
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
    ) -> io::Result<Option<()>> {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        let Some(fd_permit) = self.reserve_descriptors() else {
            return Ok(None);
        };
        let pipes = match SplicePipes::new(fd_permit) {
            Ok(pipes) => pipes,
            Err(_) => return Ok(None),
        };
        let _permit = permit;
        let uplink = splice_direction(
            inbound,
            outbound,
            &pipes.uplink,
            self.chunk_bytes,
            ledger,
            true,
        );
        let downlink = splice_direction(
            outbound,
            inbound,
            &pipes.downlink,
            self.chunk_bytes,
            ledger,
            false,
        );
        tokio::try_join!(uplink, downlink)?;
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
    ) -> io::Result<Option<()>> {
        let Ok(_permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        let Some(fd_permit) = self.fd_budget.try_acquire(UNITS_SPLICE_DIRECTION) else {
            return Ok(None);
        };
        // The permit is dropped — and its two units released — on every exit
        // path, together with the pipe pair it accounts for.
        let pipe = match PipePair::new() {
            Ok(pipe) => pipe,
            Err(_) => return Ok(None),
        };
        let _fd_permit = fd_permit;
        splice_owned_direction(
            source,
            destination,
            &pipe,
            self.chunk_bytes,
            ledger,
            direction.is_inbound_to_outbound(),
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
}

#[cfg(target_os = "linux")]
impl PipePair {
    fn new() -> io::Result<Self> {
        let (read, write) = rustix::pipe::pipe_with(
            rustix::pipe::PipeFlags::CLOEXEC | rustix::pipe::PipeFlags::NONBLOCK,
        )
        .map_err(io::Error::from)?;
        Ok(Self { read, write })
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
) -> io::Result<()> {
    splice_pump(
        source,
        destination,
        pipe,
        chunk_bytes,
        ledger,
        inbound_to_outbound,
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
) -> io::Result<()> {
    splice_pump(
        source.as_ref(),
        destination.as_ref(),
        pipe,
        chunk_bytes,
        ledger,
        inbound_to_outbound,
    )
    .await?;
    destination.shutdown().await
}

/// Moves bytes source -> pipe -> destination until source EOF.
///
/// Every transferred byte is recorded in the shared ledger only after the
/// destination accepted it, so a byte is never claimed before it moved.
#[cfg(target_os = "linux")]
async fn splice_pump(
    source: &TcpStream,
    destination: &TcpStream,
    pipe: &PipePair,
    chunk_bytes: usize,
    ledger: &TransferLedger,
    inbound_to_outbound: bool,
) -> io::Result<()> {
    use tokio::io::Interest;

    let flags = rustix::pipe::SpliceFlags::MOVE | rustix::pipe::SpliceFlags::NONBLOCK;
    loop {
        let read = source
            .async_io(Interest::READABLE, || {
                splice_retry(source, &pipe.write, chunk_bytes, flags)
            })
            .await?;
        if read == 0 {
            return Ok(());
        }

        let mut pending = read;
        while pending != 0 {
            let written = destination
                .async_io(Interest::WRITABLE, || {
                    splice_retry(&pipe.read, destination, pending, flags)
                })
                .await?;
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
    use std::{io, net::Ipv4Addr, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time,
    };

    use super::TcpRelay;
    use crate::{
        config::RelayPolicy,
        runtime::FdBudget,
        transport::{BackendRequest, DirectionalRelayOutcome, RelayBackend, RelayDirection},
    };

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_buffered_relay_preserves_half_close() {
        let relay = TcpRelay::new(
            &RelayPolicy {
                buffer_bytes: 4 * 1024,
                max_pooled_buffers: 2,
                max_splice_relays: 0,
                max_io_uring_relays: 0,
                max_sockhash_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                max_pinned_memory_bytes: u64::MAX,
                splice: false,
                io_uring: false,
                sockhash: false,
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
                max_io_uring_relays: 0,
                max_sockhash_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                max_pinned_memory_bytes: u64::MAX,
                splice: true,
                io_uring: false,
                sockhash: false,
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
            "a bidirectional splice relay creates two pipe pairs and must reserve all four"
        );
        assert_eq!(
            budget.in_use(),
            0,
            "pipe descriptors and their permit must be released on completion"
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
        assert_eq!(budget.in_use(), 0);
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
            assert_eq!(
                budget.in_use(),
                0,
                "every cycle must return the counter to baseline"
            );
        }
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
            max_io_uring_relays: 0,
            max_sockhash_relays: 0,
            max_relay_memory_bytes: u64::MAX,
            max_pinned_memory_bytes: u64::MAX,
            splice: true,
            io_uring: false,
            sockhash: false,
        }
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
            let relay_io = relay.relay_direction(source_reader, sink_writer, direction, request);
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
                max_io_uring_relays: 0,
                max_sockhash_relays: 0,
                max_relay_memory_bytes: u64::MAX,
                max_pinned_memory_bytes: u64::MAX,
                splice: false,
                io_uring: false,
                sockhash: false,
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
        assert_eq!(
            budget.in_use(),
            0,
            "the pipe descriptors and their permit must be released on completion"
        );
        assert_eq!(budget.underflows(), 0);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn repeated_directional_splice_relays_return_descriptor_units_to_baseline() {
        let budget = FdBudget::new(64);
        let relay = TcpRelay::new(&splice_policy(), budget.clone()).expect("relay must compile");
        for _ in 0..8 {
            let (outcome, _) = run_one_direction(
                &relay,
                RelayDirection::Downlink,
                BackendRequest::Automatic,
                b"x",
            )
            .await;
            outcome.expect("directional relay must succeed");
            assert_eq!(
                budget.in_use(),
                0,
                "every cycle must return the counter to baseline"
            );
        }
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
}
