//! TCP relay over one authenticated LINE, preserving each half-close.
use super::vision_io::VisionIo;
pub(super) use super::vision_io::VisionTunnelError;
use crate::protocol::{
    reality::ClientSession,
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
        let expired = activity.expired(crate::io_activity::SESSION_IDLE_WINDOW);
        tokio::pin!(expired);
        loop {
            tokio::select! {
                () = &mut expired => return Err(VisionTunnelError::Tls(
                    crate::protocol::reality::tls13::TlsApplicationIoError::Timeout)),
                ready = self.io.poll_fill_readable(), if download_open => {
                    match ready {
                        Err(VisionTunnelError::Closed | VisionTunnelError::Tls(crate::protocol::reality::tls13::TlsApplicationIoError::PeerAlert { description: 0, .. })) => {
                            local.shutdown().await.map_err(VisionTunnelError::Io)?;
                            download_open = false;
                            if !upload_open { return Ok(()); }
                            continue;
                        }
                        other => other?,
                    }
                    if self.io.readable_at < self.io.readable.len() {
                        let chunk = &self.io.readable[self.io.readable_at..];
                        local.write_all(chunk).await.map_err(VisionTunnelError::Io)?;
                        local.flush().await.map_err(VisionTunnelError::Io)?;
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
