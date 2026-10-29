//! TCP relay over one authenticated LINE, preserving each half-close.
use super::vision_io::VisionIo;
pub(super) use super::vision_io::VisionTunnelError;
use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{IdleDeadline, IdleError, TlsApplicationIoError},
    },
    vless::{Destination, UserId, encode_vision_tcp_request},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bidirectional Vision tunnel to a destination through an entry.
pub struct VisionTunnel {
    io: VisionIo,
}

impl VisionTunnel {
    /// Sends the Vision TCP request preamble and waits for the VLESS response.
    pub async fn connect(
        stream: tokio::net::TcpStream,
        session: ClientSession,
        user_id: UserId,
        destination: &Destination,
    ) -> Result<Self, VisionTunnelError> {
        let mut request = [0_u8; 512];
        let len = encode_vision_tcp_request(user_id, destination, &mut request)
            .map_err(|_| VisionTunnelError::Request)?;
        let mut io = VisionIo::connect(stream, session, user_id, &request[..len]).await?;
        io.await_response().await?;
        Ok(Self { io })
    }

    /// Relays application bytes between a local SOCKS stream and this tunnel.
    pub async fn relay<S>(&mut self, local: &mut S) -> Result<(), VisionTunnelError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut local_buf = vec![0_u8; 16 * 1024];
        let mut upload_open = true;
        let mut download_open = true;
        let activity = self.io.activity.clone();
        let mut local_write = IdleDeadline::new();
        local_write.set_activity(activity.clone());
        local_write
            .reset(crate::io_activity::WRITE_STALL_TIMEOUT)
            .map_err(local_io_failure)?;
        let expired = activity.expired(crate::io_activity::SESSION_IDLE_WINDOW);
        tokio::pin!(expired);
        loop {
            tokio::select! {
                () = &mut expired => return Err(VisionTunnelError::Tls(
                    crate::protocol::reality::tls13::TlsApplicationIoError::Timeout)),
                ready = self.io.poll_fill_readable(), if download_open => {
                    match ready {
                        Err(VisionTunnelError::Closed | VisionTunnelError::Tls(crate::protocol::reality::tls13::TlsApplicationIoError::PeerAlert { description: 0, .. })) => {
                            local_write.shutdown(local).await.map_err(local_io_failure)?;
                            download_open = false;
                            if !upload_open { return Ok(()); }
                            continue;
                        }
                        other => other?,
                    }
                    if self.io.readable_at < self.io.readable.len() {
                        let chunk = &self.io.readable[self.io.readable_at..];
                        write_local(&mut local_write, local, chunk).await?;
                        self.io.readable_at = self.io.readable.len();
                        if self.io.readable_at > 64 * 1024 {
                            self.io.readable.clear();
                            self.io.readable_at = 0;
                        }
                    }
                }
                read = local.read(&mut local_buf), if upload_open => {
                    let n = read.map_err(VisionTunnelError::Io)?;
                    if n == 0 {
                        self.io.shutdown().await?;
                        upload_open = false;
                        if !download_open { return Ok(()); }
                        continue;
                    }
                    self.io.write_application(&local_buf[..n]).await?;
                }
            }
        }
    }
}

async fn write_local<S: AsyncWrite + Unpin>(
    deadline: &mut IdleDeadline,
    local: &mut S,
    chunk: &[u8],
) -> Result<(), VisionTunnelError> {
    deadline
        .write_all(local, chunk)
        .await
        .map_err(local_io_failure)?;
    tokio::time::timeout(crate::io_activity::WRITE_STALL_TIMEOUT, local.flush())
        .await
        .map_err(|_| local_io_failure(IdleError::Timeout))?
        .map_err(VisionTunnelError::Io)
}

fn local_io_failure(error: IdleError) -> VisionTunnelError {
    match error {
        IdleError::Timeout => VisionTunnelError::Tls(TlsApplicationIoError::Timeout),
        IdleError::Io(error) => VisionTunnelError::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn local_reader_stall_expires_after_partial_progress() {
        let (mut local, mut peer) = tokio::io::duplex(1);
        let mut deadline = IdleDeadline::new();
        deadline.set_activity(std::sync::Arc::default());
        deadline
            .reset(crate::io_activity::WRITE_STALL_TIMEOUT)
            .unwrap();
        let start = tokio::time::Instant::now();
        assert!(matches!(
            write_local(&mut deadline, &mut local, b"ab").await,
            Err(VisionTunnelError::Tls(TlsApplicationIoError::Timeout))
        ));
        assert_eq!(start.elapsed(), crate::io_activity::WRITE_STALL_TIMEOUT);
        let mut received = [0];
        peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received, *b"a");
    }
}
