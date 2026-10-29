//! Vision tunnel over an established REALITY TLS client session.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{
            MAX_PLAINTEXT_LEN, TlsApplicationReader, TlsApplicationWriter, application_halves,
        },
    },
    vless::{
        Destination, ResponseDecodeError, UserId, VisionCommand, VisionDecoder, VisionEncoder,
        VisionMode, decode_response, encode_vision_tcp_request,
    },
};

/// Vision / VLESS session failure.
#[derive(Debug)]
pub enum VisionTunnelError {
    /// VLESS request could not be encoded.
    Request,
    /// Vision framing failed.
    Vision,
    /// Record protection failed.
    Record,
    /// Peer closed before the VLESS response.
    ClosedBeforeResponse,
    /// Socket I/O failed.
    Io(io::Error),
    /// Authenticated TLS application transport failed.
    Tls(crate::protocol::reality::tls13::TlsApplicationIoError),
}

impl std::fmt::Display for VisionTunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vision tunnel failed")
    }
}

impl std::error::Error for VisionTunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tls(e) => Some(e),
            _ => None,
        }
    }
}

/// Bidirectional Vision tunnel to a destination through an entry.
pub struct VisionTunnel {
    reader: TlsApplicationReader<tokio::net::tcp::OwnedReadHalf>,
    writer: TlsApplicationWriter<tokio::net::tcp::OwnedWriteHalf>,
    encoder: VisionEncoder,
    decoder: VisionDecoder,
    downlink: VisionMode,
    readable: Vec<u8>,
    readable_at: usize,
    encoder_done: bool,
    activity: std::sync::Arc<crate::io_activity::SessionActivity>,
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
        let request_len = encode_vision_tcp_request(user_id, destination, &mut request)
            .map_err(|_| VisionTunnelError::Request)?;
        let mut encoder = VisionEncoder::new(user_id).map_err(|_| VisionTunnelError::Vision)?;
        let preamble = encoder
            .plan(0, VisionCommand::Continue, true)
            .map_err(|_| VisionTunnelError::Vision)?;
        let total = request_len
            .checked_add(preamble.wire_len())
            .filter(|n| *n <= MAX_PLAINTEXT_LEN)
            .ok_or(VisionTunnelError::Request)?;
        let mut frame = vec![0_u8; total];
        frame[..request_len].copy_from_slice(&request[..request_len]);
        encoder.assemble(&preamble, &[], &mut frame[request_len..]);
        encoder.commit(&preamble);

        let (_, write_records, read_records) = session.into_record_layers();
        let (reader, writer) = stream.into_split();
        let (mut reader, mut writer) = application_halves(
            reader,
            Vec::new(),
            writer,
            read_records,
            write_records,
            false,
        );
        let activity = std::sync::Arc::new(crate::io_activity::SessionActivity::default());
        reader.set_activity(activity.clone());
        writer.set_activity(activity.clone());
        writer
            .write_application(&frame, crate::io_activity::WRITE_STALL_TIMEOUT)
            .await
            .map_err(VisionTunnelError::Tls)?;

        let mut tunnel = Self {
            reader,
            writer,
            encoder,
            decoder: VisionDecoder::new(user_id),
            downlink: VisionMode::Framed,
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            encoder_done: false,
            activity,
        };
        tunnel.await_response().await?;
        Ok(tunnel)
    }

    async fn await_response(&mut self) -> Result<(), VisionTunnelError> {
        // First downlink record is `[VERSION, addons_len, …addons] || Vision…`.
        // Peel the VLESS response before any Vision decode.
        let mut response_buf = Vec::new();
        loop {
            let plaintext = self.read_raw_application().await?;
            if plaintext.is_empty() {
                continue;
            }
            response_buf.extend_from_slice(&plaintext);
            match decode_response(&response_buf) {
                Ok(decoded) => {
                    let payload = decoded.payload().to_vec();
                    self.readable.clear();
                    self.readable_at = 0;
                    if !payload.is_empty() {
                        self.ingest_plaintext(&payload)?;
                    }
                    return Ok(());
                }
                Err(ResponseDecodeError::Incomplete { .. }) => continue,
                Err(_) => return Err(VisionTunnelError::Request),
            }
        }
    }

    async fn read_and_open_record(&mut self) -> Result<(), VisionTunnelError> {
        let plaintext = self.read_raw_application().await?;
        if plaintext.is_empty() {
            return Ok(());
        }
        self.ingest_plaintext(&plaintext)
    }

    /// Opens one application-data record (or skips ChangeCipherSpec) and returns
    /// the plaintext bytes without Vision framing.
    async fn read_raw_application(&mut self) -> Result<Vec<u8>, VisionTunnelError> {
        let record = self
            .reader
            .read_application(crate::io_activity::SESSION_IDLE_WINDOW)
            .await
            .map_err(VisionTunnelError::Tls)?;
        Ok(record.plaintext().to_vec())
    }

    fn ingest_plaintext(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        match self.downlink {
            VisionMode::Direct | VisionMode::Raw => {
                self.readable.extend_from_slice(plaintext);
                Ok(())
            }
            VisionMode::Framed => {
                let mut staged = Vec::new();
                let mode = self
                    .decoder
                    .decode_append(plaintext, &mut staged)
                    .map_err(|_| VisionTunnelError::Vision)?;
                self.readable.extend_from_slice(&staged);
                self.downlink = mode;
                if matches!(mode, VisionMode::Direct) {
                    self.encoder_done = true;
                }
                Ok(())
            }
        }
    }

    /// Relays application bytes between a local SOCKS stream and this tunnel.
    pub async fn relay<S>(&mut self, local: &mut S) -> Result<(), VisionTunnelError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut local_buf = vec![0_u8; 16 * 1024];
        let mut upload_open = true;
        let mut download_open = true;
        let activity = self.activity.clone();
        let expired = activity.expired(crate::io_activity::SESSION_IDLE_WINDOW);
        tokio::pin!(expired);
        loop {
            tokio::select! {
                () = &mut expired => return Err(VisionTunnelError::Tls(
                    crate::protocol::reality::tls13::TlsApplicationIoError::Timeout)),
                ready = self.poll_fill_readable(), if download_open => {
                    match ready {
                        Err(VisionTunnelError::Tls(crate::protocol::reality::tls13::TlsApplicationIoError::PeerAlert { description: 0, .. })) => {
                            local.shutdown().await.map_err(VisionTunnelError::Io)?;
                            download_open = false;
                            if !upload_open { return Ok(()); }
                            continue;
                        }
                        other => other?,
                    }
                    if self.readable_at < self.readable.len() {
                        let chunk = &self.readable[self.readable_at..];
                        local.write_all(chunk).await.map_err(VisionTunnelError::Io)?;
                        local.flush().await.map_err(VisionTunnelError::Io)?;
                        self.readable_at = self.readable.len();
                        if self.readable_at > 64 * 1024 {
                            self.readable.clear();
                            self.readable_at = 0;
                        }
                    }
                }
                read = local.read(&mut local_buf), if upload_open => {
                    let n = read.map_err(VisionTunnelError::Io)?;
                    if n == 0 {
                        self.writer.shutdown(crate::io_activity::WRITE_STALL_TIMEOUT)
                            .await.map_err(VisionTunnelError::Tls)?;
                        upload_open = false;
                        if !download_open { return Ok(()); }
                        continue;
                    }
                    self.write_application(&local_buf[..n]).await?;
                }
            }
        }
    }

    async fn poll_fill_readable(&mut self) -> Result<(), VisionTunnelError> {
        if self.readable_at < self.readable.len() {
            return Ok(());
        }
        self.read_and_open_record().await
    }

    async fn write_application(&mut self, payload: &[u8]) -> Result<(), VisionTunnelError> {
        if payload.is_empty() {
            return Ok(());
        }
        if self.encoder_done {
            return self.seal_and_send(payload).await;
        }
        let mut offset = 0;
        while offset < payload.len() {
            // The preamble already consumed the UUID; reserve the five-byte frame header.
            let want = (payload.len() - offset).min(crate::protocol::vless::VISION_FRAME_SIZE - 5);
            let plan = self
                .encoder
                .plan(want, VisionCommand::Continue, false)
                .map_err(|_| VisionTunnelError::Vision)?;
            let content = &payload[offset..offset + want];
            self.writer
                .write_assembled(
                    plan.wire_len(),
                    |frame| {
                        self.encoder.assemble(&plan, content, frame);
                    },
                    crate::io_activity::WRITE_STALL_TIMEOUT,
                )
                .await
                .map_err(VisionTunnelError::Tls)?;
            self.encoder.commit(&plan);
            offset += want;
        }
        Ok(())
    }

    async fn seal_and_send(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        self.writer
            .write_application(plaintext, crate::io_activity::WRITE_STALL_TIMEOUT)
            .await
            .map(|_| ())
            .map_err(VisionTunnelError::Tls)
    }
}
