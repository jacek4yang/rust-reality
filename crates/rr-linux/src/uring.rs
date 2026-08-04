//! A bounded io_uring driver and relay backend.
//!
//! # Why this shape
//!
//! * **Bounded shards.** `min(visible CPUs, Budget::max_shards)` threads, each
//!   owning exactly one ring. A ring is created on the thread that submits to
//!   it, which is required for the setup flags this driver may use.
//! * **Bounded submission.** Work reaches a shard through a
//!   [`std::sync::mpsc::sync_channel`] with a fixed capacity. There is no
//!   unbounded sender anywhere in this crate.
//! * **Bounded in-flight operations.** Each shard tracks a fixed slot table.
//!   A submission that finds no free slot is refused rather than queued.
//! * **Idempotent completion.** Every slot carries a generation counter; the
//!   `user_data` of an SQE is `(index << 32) | generation`. A stale or duplicated
//!   completion whose generation does not match the slot is discarded.
//! * **Owned descriptors.** A relay session duplicates both descriptors and owns
//!   them until every completion has been reaped, so a numeric descriptor reused
//!   elsewhere in the process can never be acted on by an old operation.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
};

use io_uring::{IoUring, opcode, types};

use crate::{
    Budget, BudgetError,
    capability::{DeclineReason, Probe, ProbeReport},
};

/// The backend name used in capability reports.
pub const BACKEND: &str = "io_uring";

/// One operation the driver can submit.
pub enum Operation {
    /// Receive into an owned buffer.
    Recv {
        /// The descriptor to read from.
        fd: RawFd,
        /// Buffer owned by the driver until the completion is reaped.
        buffer: Box<[u8]>,
    },
    /// Send an owned buffer prefix.
    Send {
        /// The descriptor to write to.
        fd: RawFd,
        /// Buffer owned by the driver until the completion is reaped.
        buffer: Box<[u8]>,
        /// Bytes of `buffer` to send.
        length: usize,
    },
    /// Shut down one direction of a socket.
    Shutdown {
        /// The descriptor to shut down.
        fd: RawFd,
        /// The `SHUT_*` constant.
        how: i32,
    },
}

/// A completed operation: the kernel result plus any returned buffer.
pub struct Completion {
    /// The raw `cqe.result()`; negative values are negated `errno`.
    pub result: i32,
    /// The buffer the operation owned, returned to the caller.
    pub buffer: Option<Box<[u8]>>,
}

impl Completion {
    /// Converts a negative kernel result into an [`io::Error`].
    ///
    /// # Errors
    ///
    /// Returns the kernel error when `result` is negative.
    pub fn into_transferred(self) -> io::Result<(usize, Option<Box<[u8]>>)> {
        if self.result < 0 {
            return Err(io::Error::from_raw_os_error(-self.result));
        }
        let transferred = usize::try_from(self.result)
            .map_err(|_| io::Error::other("io_uring returned an unrepresentable length"))?;
        Ok((transferred, self.buffer))
    }
}

struct Slot {
    generation: u32,
    buffer: Option<Box<[u8]>>,
    reply: Option<tokio_oneshot::Sender>,
}

/// A minimal single-slot reply channel.
///
/// A full async channel is unnecessary: exactly one value is ever sent, and the
/// waiter is a single task. Keeping it local avoids adding an async runtime
/// dependency to this crate and keeps the per-operation footprint one `Mutex`
/// plus one `Condvar`-free `Waker` slot.
mod tokio_oneshot {
    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll, Waker},
    };

    use super::Completion;

    #[derive(Default)]
    struct Shared {
        value: Option<Completion>,
        waker: Option<Waker>,
        closed: bool,
    }

    /// The sending half, owned by a driver slot.
    pub(super) struct Sender(Arc<Mutex<Shared>>);

    /// The receiving half, awaited by the relay session.
    pub(super) struct Receiver(Arc<Mutex<Shared>>);

    /// Creates one single-use completion channel.
    #[must_use]
    pub(super) fn channel() -> (Sender, Receiver) {
        let shared = Arc::new(Mutex::new(Shared::default()));
        (Sender(Arc::clone(&shared)), Receiver(shared))
    }

    impl Sender {
        /// Delivers the completion and wakes the waiter.
        pub(super) fn send(self, value: Completion) {
            let waker = {
                let mut shared = lock(&self.0);
                shared.value = Some(value);
                shared.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    impl Drop for Sender {
        fn drop(&mut self) {
            let waker = {
                let mut shared = lock(&self.0);
                if shared.value.is_some() {
                    return;
                }
                shared.closed = true;
                shared.waker.take()
            };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    impl Future for Receiver {
        type Output = Option<Completion>;

        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            let mut shared = lock(&self.0);
            if let Some(value) = shared.value.take() {
                return Poll::Ready(Some(value));
            }
            if shared.closed {
                return Poll::Ready(None);
            }
            shared.waker = Some(context.waker().clone());
            Poll::Pending
        }
    }

    fn lock(mutex: &Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

enum Message {
    Submit {
        operation: Operation,
        reply: tokio_oneshot::Sender,
    },
}

struct Shard {
    submit: Option<SyncSender<Message>>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

/// A bounded io_uring driver owning every ring in the process.
pub struct UringDriver {
    shards: Vec<Shard>,
    next: AtomicUsize,
    budget: Budget,
}

impl UringDriver {
    /// Creates one driver with a bounded number of shards.
    ///
    /// Every shard creates its ring on its own thread and reports success or the
    /// exact kernel error before the driver is considered usable.
    ///
    /// # Errors
    ///
    /// Returns the budget error for an impossible configuration, or the fixed
    /// decline reason produced by the failing ring creation.
    pub fn new(budget: Budget, visible_cpus: usize) -> Result<Self, DriverError> {
        budget.validate().map_err(DriverError::Budget)?;
        let shard_count = budget.shards(visible_cpus);
        let mut shards = Vec::with_capacity(shard_count);
        for index in 0..shard_count {
            let (submit, receive) = sync_channel(usize::from(budget.queue_depth));
            let (ready_tx, ready_rx) = sync_channel::<Result<(), i32>>(1);
            let depth = budget.queue_depth;
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shard_shutdown = Arc::clone(&shutdown);
            let handle = thread::Builder::new()
                .name(format!("rr-uring-{index}"))
                .spawn(move || run_shard(depth, &receive, &ready_tx, &shard_shutdown))
                .map_err(|_| DriverError::Declined(DeclineReason::ResourceLimit))?;
            match ready_rx.recv() {
                Ok(Ok(())) => shards.push(Shard {
                    submit: Some(submit),
                    shutdown,
                    handle: Some(handle),
                }),
                Ok(Err(errno)) => {
                    let error = io::Error::from_raw_os_error(errno);
                    return Err(DriverError::Declined(DeclineReason::from_errno(&error)));
                }
                Err(_) => return Err(DriverError::Declined(DeclineReason::InitializationFailure)),
            }
        }
        if shards.is_empty() {
            return Err(DriverError::Declined(DeclineReason::QueueUnavailable));
        }
        Ok(Self {
            shards,
            next: AtomicUsize::new(0),
            budget,
        })
    }

    /// Returns the configured budget.
    #[must_use]
    pub const fn budget(&self) -> Budget {
        self.budget
    }

    /// Returns how many shards were actually created.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Submits one operation, refusing rather than queueing when full.
    ///
    /// # Errors
    ///
    /// Returns [`SubmitError::WouldBlock`] when the bounded channel is full,
    /// which is the explicit submission backpressure signal, and
    /// [`SubmitError::Closed`] when the shard has shut down.
    pub fn submit(&self, operation: Operation) -> Result<CompletionFuture, SubmitError> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.shards.len();
        let shard = self.shards.get(index).ok_or(SubmitError::Closed)?;
        let sender = shard.submit.as_ref().ok_or(SubmitError::Closed)?;
        let (reply, receiver) = tokio_oneshot::channel();
        match sender.try_send(Message::Submit { operation, reply }) {
            Ok(()) => Ok(CompletionFuture(receiver)),
            Err(TrySendError::Full(_)) => Err(SubmitError::WouldBlock),
            Err(TrySendError::Disconnected(_)) => Err(SubmitError::Closed),
        }
    }
}

impl std::fmt::Debug for UringDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UringDriver")
            .field("shards", &self.shards.len())
            .field("queue_depth", &self.budget.queue_depth)
            .finish_non_exhaustive()
    }
}

impl Drop for UringDriver {
    fn drop(&mut self) {
        // The shutdown flag is checked every loop iteration, so a shard whose
        // bounded channel is full still terminates deterministically. Closing
        // the sender afterwards releases a shard parked on `recv`.
        for shard in &mut self.shards {
            shard
                .shutdown
                .store(true, std::sync::atomic::Ordering::Release);
            let _ignored = shard.submit.take();
        }
        for shard in &mut self.shards {
            if let Some(handle) = shard.handle.take() {
                let _ignored = handle.join();
            }
        }
    }
}

/// A pending completion.
pub struct CompletionFuture(tokio_oneshot::Receiver);

impl std::future::Future for CompletionFuture {
    type Output = io::Result<Completion>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match std::pin::Pin::new(&mut self.0).poll(context) {
            std::task::Poll::Ready(Some(completion)) => std::task::Poll::Ready(Ok(completion)),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Err(io::Error::other(
                "io_uring shard dropped an operation before completion",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Driver construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverError {
    /// The configured budget is impossible.
    Budget(BudgetError),
    /// The kernel or policy refused, with a fixed reason.
    Declined(DeclineReason),
}

impl std::fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Budget(source) => source.fmt(formatter),
            Self::Declined(reason) => write!(formatter, "io_uring declined: {reason}"),
        }
    }
}

impl std::error::Error for DriverError {}

/// A submission was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitError {
    /// The bounded submission channel is full; this is backpressure, not failure.
    WouldBlock,
    /// The shard has shut down.
    Closed,
}

impl std::fmt::Display for SubmitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::WouldBlock => "io_uring submission queue is full",
            Self::Closed => "io_uring driver is shut down",
        })
    }
}

impl std::error::Error for SubmitError {}

/// Runs one shard: owns the ring, submits, and reaps completions.
fn run_shard(
    depth: u16,
    receive: &Receiver<Message>,
    ready: &SyncSender<Result<(), i32>>,
    shutdown: &std::sync::atomic::AtomicBool,
) {
    let ring = match IoUring::new(u32::from(depth)) {
        Ok(ring) => {
            let _ignored = ready.send(Ok(()));
            ring
        }
        Err(error) => {
            let _ignored = ready.send(Err(error.raw_os_error().unwrap_or(libc::EIO)));
            return;
        }
    };
    let mut ring = ring;
    let capacity = usize::from(depth);
    let mut slots: Vec<Option<Slot>> = (0..capacity).map(|_| None).collect();
    let mut generations = vec![0_u32; capacity];
    let mut in_flight = 0_usize;
    let mut shutting_down = false;

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Acquire) {
            shutting_down = true;
        }
        // Accept new work only while a slot is free. A full slot table exerts
        // backpressure through the bounded channel rather than growing.
        while !shutting_down && in_flight < capacity {
            let message = if in_flight == 0 {
                match receive.recv() {
                    Ok(message) => message,
                    Err(_) => {
                        shutting_down = true;
                        break;
                    }
                }
            } else {
                match receive.try_recv() {
                    Ok(message) => message,
                    Err(_) => break,
                }
            };
            match message {
                Message::Submit { operation, reply } => {
                    let Some(index) = slots.iter().position(Option::is_none) else {
                        // Unreachable while in_flight < capacity, but refuse
                        // rather than assume.
                        drop(reply);
                        break;
                    };
                    let generation = generations[index].wrapping_add(1);
                    generations[index] = generation;
                    let user_data = (u64::from(u32::try_from(index).unwrap_or(u32::MAX)) << 32)
                        | u64::from(generation);
                    let (entry, buffer) = build_entry(operation, user_data);
                    slots[index] = Some(Slot {
                        generation,
                        buffer,
                        reply: Some(reply),
                    });
                    // SAFETY: `entry` points into the buffer stored in
                    // `slots[index]`, which stays alive and unmoved (it is a
                    // boxed slice behind an `Option` that is only taken when the
                    // matching completion is reaped). The descriptor is owned by
                    // the caller's session for at least as long as the
                    // completion, so the kernel never touches freed memory or a
                    // recycled descriptor.
                    let pushed = unsafe { ring.submission().push(&entry) };
                    if pushed.is_err() {
                        if let Some(mut slot) = slots[index].take()
                            && let Some(reply) = slot.reply.take()
                        {
                            reply.send(Completion {
                                result: -libc::EAGAIN,
                                buffer: slot.buffer.take(),
                            });
                        }
                        break;
                    }
                    in_flight += 1;
                }
            }
        }

        if in_flight == 0 {
            if shutting_down {
                return;
            }
            continue;
        }

        if ring.submit_and_wait(1).is_err() {
            // A failed submit leaves every in-flight slot unreapable; fail them
            // all explicitly rather than leaking their waiters.
            fail_all(&mut slots, &mut in_flight);
            if shutting_down {
                return;
            }
            continue;
        }

        let mut completion = ring.completion();
        completion.sync();
        for cqe in &mut completion {
            let user_data = cqe.user_data();
            let index = usize::try_from(user_data >> 32).unwrap_or(usize::MAX);
            let generation = (user_data & 0xffff_ffff) as u32;
            let Some(entry) = slots.get_mut(index) else {
                continue;
            };
            let Some(slot) = entry else {
                // A duplicate or stale completion for a released slot.
                continue;
            };
            if slot.generation != generation {
                // A completion belonging to a previous user of this slot.
                continue;
            }
            let mut slot = entry.take().unwrap_or_else(unreachable_slot);
            in_flight = in_flight.saturating_sub(1);
            if let Some(reply) = slot.reply.take() {
                reply.send(Completion {
                    result: cqe.result(),
                    buffer: slot.buffer.take(),
                });
            }
        }
    }
}

fn unreachable_slot() -> Slot {
    Slot {
        generation: 0,
        buffer: None,
        reply: None,
    }
}

fn fail_all(slots: &mut [Option<Slot>], in_flight: &mut usize) {
    for entry in slots.iter_mut() {
        if let Some(mut slot) = entry.take()
            && let Some(reply) = slot.reply.take()
        {
            reply.send(Completion {
                result: -libc::ECANCELED,
                buffer: slot.buffer.take(),
            });
        }
    }
    *in_flight = 0;
}

fn build_entry(
    operation: Operation,
    user_data: u64,
) -> (io_uring::squeue::Entry, Option<Box<[u8]>>) {
    match operation {
        Operation::Recv { fd, mut buffer } => {
            let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            let pointer = buffer.as_mut_ptr();
            let entry = opcode::Recv::new(types::Fd(fd), pointer, length)
                .build()
                .user_data(user_data);
            (entry, Some(buffer))
        }
        Operation::Send { fd, buffer, length } => {
            let length = u32::try_from(length.min(buffer.len())).unwrap_or(u32::MAX);
            let pointer = buffer.as_ptr();
            let entry = opcode::Send::new(types::Fd(fd), pointer, length)
                .build()
                .user_data(user_data);
            (entry, Some(buffer))
        }
        Operation::Shutdown { fd, how } => {
            let entry = opcode::Shutdown::new(types::Fd(fd), how)
                .build()
                .user_data(user_data);
            (entry, None)
        }
    }
}

/// Probes every io_uring operation this backend actually uses.
///
/// The probe creates a real ring and asks the kernel which operations it
/// supports, so a kernel that lacks `recv`, `send`, `shutdown` or async cancel
/// declines with a fixed reason instead of failing at the first connection.
#[must_use]
pub fn probe() -> ProbeReport {
    if !cfg!(target_os = "linux") {
        return ProbeReport::declined(BACKEND, DeclineReason::UnsupportedOperatingSystem);
    }
    let ring = IoUring::new(8);
    let report = ProbeReport::new(BACKEND).with("ring", Probe::from_result(&ring));
    let Ok(ring) = ring else {
        return report;
    };
    let mut probe = io_uring::Probe::new();
    if ring.submitter().register_probe(&mut probe).is_err() {
        return report.with(
            "register_probe",
            Probe::Declined(DeclineReason::MissingOperation),
        );
    }
    report
        .with("recv", supported(&probe, opcode::Recv::CODE))
        .with("send", supported(&probe, opcode::Send::CODE))
        .with("shutdown", supported(&probe, opcode::Shutdown::CODE))
        .with("async_cancel", supported(&probe, opcode::AsyncCancel::CODE))
}

fn supported(probe: &io_uring::Probe, code: u8) -> Probe {
    if probe.is_supported(code) {
        Probe::Available
    } else {
        Probe::Declined(DeclineReason::MissingOperation)
    }
}

/// A pair of descriptors owned for the whole life of one io_uring relay.
///
/// Duplicating both descriptors is what makes numeric descriptor reuse safe: an
/// operation submitted for this session can only ever refer to the duplicate,
/// which stays open until the session drops.
pub struct SessionFds {
    inbound: OwnedFd,
    outbound: OwnedFd,
}

impl SessionFds {
    /// Duplicates both descriptors for exclusive session ownership.
    ///
    /// # Errors
    ///
    /// Returns the kernel error from `dup`.
    pub fn duplicate(inbound: RawFd, outbound: RawFd) -> io::Result<Self> {
        Ok(Self {
            inbound: duplicate(inbound)?,
            outbound: duplicate(outbound)?,
        })
    }

    /// Returns the duplicated inbound descriptor.
    #[must_use]
    pub fn inbound(&self) -> RawFd {
        self.inbound.as_raw_fd()
    }

    /// Returns the duplicated outbound descriptor.
    #[must_use]
    pub fn outbound(&self) -> RawFd {
        self.outbound.as_raw_fd()
    }
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` returns a fresh descriptor owned by this
    // process, or -1. The success value is immediately wrapped in `OwnedFd`,
    // which is the sole owner and closes it exactly once.
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `duplicated` is a valid, freshly created descriptor that no other
    // object owns.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

/// A shared handle to the process-wide bounded driver.
pub type SharedDriver = Arc<UringDriver>;

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    use super::{Budget, DriverError, Operation, SessionFds, SubmitError, UringDriver, probe};

    const BUDGET: Budget = Budget {
        max_relays: 16,
        buffer_bytes: 4096,
        max_shards: 2,
        queue_depth: 8,
    };

    #[test]
    fn an_impossible_budget_is_rejected_before_any_ring_is_created() {
        let error = UringDriver::new(
            Budget {
                queue_depth: 3,
                ..BUDGET
            },
            1,
        )
        .expect_err("a non-power-of-two depth must be rejected");

        assert!(matches!(error, DriverError::Budget(_)));
    }

    #[test]
    fn the_probe_reports_a_fixed_reason_rather_than_panicking() {
        let report = probe();
        // The environment decides the answer; the test only requires that the
        // report is well formed and never claims an unprobed success.
        assert_eq!(report.backend(), "io_uring");
        if !report.is_available() {
            assert!(report.overall().reason().is_some());
        }
    }

    #[test]
    fn shard_count_never_exceeds_the_budget() {
        let Ok(driver) = UringDriver::new(BUDGET, 64) else {
            eprintln!("io_uring unavailable in this environment; shard test skipped");
            return;
        };
        assert!(driver.shard_count() <= usize::from(BUDGET.max_shards));
        assert!(driver.shard_count() >= 1);
    }

    fn pair() -> Option<(TcpStream, TcpStream)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).ok()?;
        let address = listener.local_addr().ok()?;
        let client = TcpStream::connect(address).ok()?;
        let (accepted, _) = listener.accept().ok()?;
        Some((client, accepted))
    }

    #[test]
    fn a_duplicated_descriptor_outlives_the_original() {
        let Some((client, accepted)) = pair() else {
            eprintln!("loopback unavailable; descriptor test skipped");
            return;
        };
        use std::os::fd::AsRawFd;
        let fds = SessionFds::duplicate(client.as_raw_fd(), accepted.as_raw_fd())
            .expect("descriptors must duplicate");
        let inbound = fds.inbound();
        drop(client);

        // The duplicate is still valid after the original is closed, which is
        // exactly what protects an in-flight operation from descriptor reuse.
        // SAFETY: `fcntl(F_GETFD)` only inspects the descriptor flags.
        let flags = unsafe { libc::fcntl(inbound, libc::F_GETFD) };
        assert!(flags >= 0, "the duplicated descriptor must stay open");
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "the duplicate must be CLOEXEC");
    }

    #[test]
    fn submission_backpressure_is_explicit_rather_than_unbounded() {
        let Ok(driver) = UringDriver::new(
            Budget {
                queue_depth: 1,
                max_shards: 1,
                ..BUDGET
            },
            1,
        ) else {
            eprintln!("io_uring unavailable in this environment; backpressure test skipped");
            return;
        };
        let Some((client, _accepted)) = pair() else {
            eprintln!("loopback unavailable; backpressure test skipped");
            return;
        };
        use std::os::fd::AsRawFd;
        client
            .set_nonblocking(false)
            .expect("blocking socket must configure");

        // The peer never writes, so each recv stays in flight. With a depth of
        // one, the bounded channel must eventually refuse instead of growing.
        let mut refused = false;
        for _ in 0..64 {
            let operation = Operation::Recv {
                fd: client.as_raw_fd(),
                buffer: vec![0_u8; 64].into_boxed_slice(),
            };
            match driver.submit(operation) {
                Ok(pending) => {
                    // Deliberately leak the pending future: the point of the
                    // test is that submission refuses, not that it completes.
                    std::mem::forget(pending);
                }
                Err(SubmitError::WouldBlock) => {
                    refused = true;
                    break;
                }
                Err(SubmitError::Closed) => break,
            }
        }
        assert!(
            refused,
            "a bounded submission channel must refuse rather than queue without limit"
        );
    }
}
