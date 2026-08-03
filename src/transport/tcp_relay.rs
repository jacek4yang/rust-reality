use std::{
    error::Error,
    fmt, io,
    sync::{Arc, Mutex, MutexGuard},
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{OwnedSemaphorePermit, Semaphore},
};

use crate::config::RelayPolicy;

use super::relay::RelayStats;

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
}

impl TcpRelay {
    /// Compiles immutable relay policy and pre-reserves all pool metadata.
    ///
    /// # Errors
    ///
    /// Returns an allocation error before any listener is bound.
    pub fn new(policy: &RelayPolicy) -> Result<Self, TcpRelayConfigError> {
        let buffers = BufferPool::new(policy.buffer_bytes, policy.max_pooled_buffers)?;
        #[cfg(target_os = "linux")]
        let splice = policy
            .splice
            .then(|| SplicePool::new(policy.max_splice_relays, policy.buffer_bytes));
        Ok(Self {
            buffers,
            #[cfg(target_os = "linux")]
            splice,
        })
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
        #[cfg(target_os = "linux")]
        if let Some(splice) = &self.splice
            && let Some(stats) = splice.try_relay(inbound, outbound).await?
        {
            return Ok(stats);
        }

        self.buffers.relay(inbound, outbound).await
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
    ) -> io::Result<RelayStats> {
        let mut pair = self.acquire_pair().await?;
        let (inbound_reader, inbound_writer) = tokio::io::split(inbound);
        let (outbound_reader, outbound_writer) = tokio::io::split(outbound);
        let (inbound_buffer, outbound_buffer) = pair.buffers_mut()?;
        let uplink = copy_direction(inbound_reader, outbound_writer, inbound_buffer);
        let downlink = copy_direction(outbound_reader, inbound_writer, outbound_buffer);
        let (inbound_to_outbound, outbound_to_inbound) = tokio::try_join!(uplink, downlink)?;
        Ok(RelayStats::new(inbound_to_outbound, outbound_to_inbound))
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

async fn copy_direction<R, W>(mut reader: R, mut writer: W, buffer: &mut [u8]) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0_u64;
    loop {
        let read = reader.read(buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }
        writer.write_all(&buffer[..read]).await?;
        total = total
            .checked_add(u64::try_from(read).map_or(u64::MAX, |value| value))
            .ok_or_else(|| io::Error::other("TCP relay byte count overflow"))?;
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
}

#[cfg(target_os = "linux")]
impl SplicePool {
    fn new(max_relays: u32, chunk_bytes: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(
                usize::try_from(max_relays).map_or(usize::MAX, |value| value),
            )),
            chunk_bytes,
        }
    }

    async fn try_relay(
        &self,
        inbound: &TcpStream,
        outbound: &TcpStream,
    ) -> io::Result<Option<RelayStats>> {
        let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
            return Ok(None);
        };
        let pipes = match SplicePipes::new() {
            Ok(pipes) => pipes,
            Err(_) => return Ok(None),
        };
        let _permit = permit;
        let uplink = splice_direction(inbound, outbound, &pipes.uplink, self.chunk_bytes);
        let downlink = splice_direction(outbound, inbound, &pipes.downlink, self.chunk_bytes);
        let (inbound_to_outbound, outbound_to_inbound) = tokio::try_join!(uplink, downlink)?;
        Ok(Some(RelayStats::new(
            inbound_to_outbound,
            outbound_to_inbound,
        )))
    }
}

#[cfg(target_os = "linux")]
struct SplicePipes {
    uplink: PipePair,
    downlink: PipePair,
}

#[cfg(target_os = "linux")]
impl SplicePipes {
    fn new() -> io::Result<Self> {
        Ok(Self {
            uplink: PipePair::new()?,
            downlink: PipePair::new()?,
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
) -> io::Result<u64> {
    use tokio::io::Interest;

    let flags = rustix::pipe::SpliceFlags::MOVE | rustix::pipe::SpliceFlags::NONBLOCK;
    let mut total = 0_u64;
    loop {
        let read = source
            .async_io(Interest::READABLE, || {
                splice_retry(source, &pipe.write, chunk_bytes, flags)
            })
            .await?;
        if read == 0 {
            rustix::net::shutdown(destination, rustix::net::Shutdown::Write)
                .map_err(io::Error::from)?;
            return Ok(total);
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
            total = total
                .checked_add(u64::try_from(written).map_or(u64::MAX, |value| value))
                .ok_or_else(|| io::Error::other("TCP relay byte count overflow"))?;
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
    use crate::config::RelayPolicy;

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_buffered_relay_preserves_half_close() {
        let relay = TcpRelay::new(&RelayPolicy {
            buffer_bytes: 4 * 1024,
            max_pooled_buffers: 2,
            max_splice_relays: 0,
            splice: false,
            io_uring: false,
            sockhash: false,
        })
        .expect("relay policy must compile");
        exercise_tcp_relay(relay).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "current_thread")]
    async fn nonblocking_splice_relay_preserves_half_close() {
        let relay = TcpRelay::new(&RelayPolicy {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 2,
            max_splice_relays: 1,
            splice: true,
            io_uring: false,
            sockhash: false,
        })
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
}
