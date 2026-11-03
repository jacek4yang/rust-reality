//! Handoff resume and landward XUDP association helpers.
//!
//! Internal to [`crate::server::vision`]: owns the landing-side TCP resume
//! entry point and the Direct/NXR/Handoff landward association enum used by
//! Vision XUDP sessions on LINE.
//! Behavior-preserving modularization only — no wire, crypto, or trust changes.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::io_activity::SessionActivity;
use crate::protocol::reality::tls13::{TlsApplicationReader, TlsApplicationWriter};
use crate::protocol::vless::UserId;
use crate::server::handoff::HandoffLineError;
use crate::server::handoff::udp::XudpHandoffUdpAssociation;
use crate::server::xudp::{
    XudpDirectAssociation, XudpEgressCapability, XudpNxrAssociation, XudpSessionError,
};
use crate::transport::TcpRelay;

use super::abort::SocketAbortGuard;
use super::error::VisionSessionError;
use super::relay::{SessionContext, join_directions};
use super::relay_downlink::relay_downlink;
use super::relay_uplink::relay_uplink;
use super::stats::{VisionRelayStats, session_stats};
use crate::server::direct::DirectHandoff;

/// Keeps the landing carrier abortable until client socket ownership is whole.
pub(super) fn reunite_handoff_client(
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    landing: &TcpStream,
) -> Result<TcpStream, VisionSessionError> {
    let mut landing_abort = SocketAbortGuard::new(landing);
    let client = reader
        .reunite(writer)
        .map_err(|_| VisionSessionError::HandoffLine(HandoffLineError::Reunite))?;
    // A guard's Drop changes the kernel socket option permanently. Disarm
    // this temporary guard before the first-downlink and relay guards take
    // over, so successful sessions retain normal FIN/half-close semantics.
    landing_abort.disarm();
    Ok(client)
}

/// Runs the standard Vision relay for a session resumed from a Handoff
/// transfer on a landing node.
///
/// The resumed halves carry the transferred generation secrets and record
/// sequences, and the reader is preloaded with the read-ahead ciphertext the
/// previous owner had already consumed from the kernel, so the client-visible
/// record stream continues exactly at the boundary. `prefetched_plaintext`
/// enters the fresh Vision decoder before any decrypted record, mirroring the
/// freshly accepted path. An owed KeyUpdate response precedes application
/// output; otherwise the response header and opening Vision frame are the
/// first client-visible server record. The transfer preserves whether it is
/// sealed at sequence zero or, after a cover-shaped empty ApplicationData
/// record, one.
pub(crate) async fn run_resumed_session(
    client_reader: TlsApplicationReader<OwnedReadHalf>,
    client_writer: TlsApplicationWriter<OwnedWriteHalf>,
    destination: tokio::net::TcpStream,
    user_id: UserId,
    prefetched_plaintext: Vec<u8>,
    relay: &TcpRelay,
    timeout: Duration,
) -> Result<VisionRelayStats, VisionSessionError> {
    let (destination_reader, destination_writer) = destination.into_split();
    // The VLESS version is fixed and this implementation never negotiates
    // response Addons.
    let response_header = [crate::protocol::vless::VERSION, 0];
    let prefetched = 0..prefetched_plaintext.len();
    let handoff = DirectHandoff::new();
    let activity = Arc::new(SessionActivity::default());
    let context = SessionContext {
        activity: &activity,
        timeout,
        handoff: &handoff,
        relay,
    };
    let uplink = relay_uplink(
        client_reader,
        destination_writer,
        user_id,
        prefetched_plaintext,
        prefetched,
        &context,
    );
    let downlink = relay_downlink(
        destination_reader,
        client_writer,
        user_id,
        &response_header,
        &context,
    );
    let (uplink, downlink) = join_directions(uplink, downlink, &activity).await?;
    Ok(session_stats(uplink, downlink))
}

/// Landward owner for one XUDP association: Direct local UDP, the NXR
/// framed TCP carrier, or the native Handoff UDP channel.
pub(super) enum XudpLandwardAssociation<'a> {
    Direct(XudpDirectAssociation<'a>),
    Nxr(XudpNxrAssociation<'a>),
    Handoff(XudpHandoffUdpAssociation<'a>),
}

impl XudpLandwardAssociation<'_> {
    pub(super) const fn capability(&self) -> XudpEgressCapability {
        match self {
            Self::Direct(_) => XudpEgressCapability::Direct,
            Self::Nxr(_) => XudpEgressCapability::Nxr,
            Self::Handoff(_) => XudpEgressCapability::Handoff,
        }
    }

    pub(super) async fn handle_uplink_packet(
        &mut self,
        packet: &crate::protocol::vless::XudpPacket,
        authorized_destination: Option<&crate::protocol::vless::Destination>,
        now: std::time::Instant,
    ) -> Result<(), XudpSessionError> {
        match self {
            Self::Direct(assoc) => {
                assoc
                    .handle_uplink_packet(packet, authorized_destination, now)
                    .await
            }
            Self::Nxr(assoc) => {
                assoc
                    .handle_uplink_packet(packet, authorized_destination, now)
                    .await
            }
            Self::Handoff(assoc) => {
                assoc
                    .handle_uplink_packet(packet, authorized_destination, now)
                    .await
            }
        }
    }

    pub(super) async fn recv_downlink_frame(
        &mut self,
        buf: &mut [u8],
        output: &mut Vec<u8>,
        now: std::time::Instant,
    ) -> Result<usize, XudpSessionError> {
        match self {
            Self::Direct(assoc) => assoc.recv_downlink_frame(buf, output, now).await,
            Self::Nxr(assoc) => assoc.recv_downlink_frame(buf, output, now).await,
            Self::Handoff(assoc) => assoc.recv_downlink_frame(buf, output, now).await,
        }
    }

    pub(super) async fn close(self, now: std::time::Instant) {
        match self {
            Self::Direct(assoc) => assoc.close(now),
            Self::Nxr(assoc) => assoc.close(now).await,
            Self::Handoff(assoc) => assoc.close(now).await,
        }
    }
}
