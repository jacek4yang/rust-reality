//! Handoff resume and landward XUDP association helpers.
//!
//! Internal to [`crate::server::vision`]: owns landing-side resume entry points
//! and the Direct/NXR landward association enum used by Vision XUDP sessions.
//! Behavior-preserving modularization only — no wire, crypto, or trust changes.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::io_activity::SessionActivity;
use crate::protocol::handoff::HandoffPolicySnapshot;
use crate::protocol::reality::tls13::{
    TlsApplicationIoError, TlsApplicationReader, TlsApplicationWriter,
};
use crate::protocol::vless::{
    UserId, VERSION, VisionCommand, VisionDecoder, VisionEncoder, VisionMode, VisionPayload,
};
use crate::server::handoff::HandoffLineError;
use crate::server::xudp::{
    XUDP_ASSOCIATION_IDLE, XudpDirectAssociation, XudpEgressCapability, XudpNxrAssociation,
    XudpSessionError, drain_xudp_frames, process_xudp_global_map,
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

/// Resumes an XUDP Vision session on LANDING after a Handoff transfer.
///
/// TLS ownership, Vision framing, and UDP sockets live here. Destination
/// authorization uses the sealed [`HandoffPolicySnapshot`] (ADR 0060 Option B
/// foundation). PR4 serves the initial destination only (`allow_destination_rewrites
/// = false`); richer multi-destination sealed policy is PR5.
pub(crate) async fn run_resumed_xudp_session(
    mut client_reader: TlsApplicationReader<OwnedReadHalf>,
    mut client_writer: TlsApplicationWriter<OwnedWriteHalf>,
    user_id: UserId,
    prefetched_plaintext: Vec<u8>,
    policy: HandoffPolicySnapshot,
    timeout: Duration,
    udp_bind_ip: Option<std::net::IpAddr>,
) -> Result<VisionRelayStats, VisionSessionError> {
    let activity = Arc::new(SessionActivity::default());
    client_writer.set_activity(Arc::clone(&activity));

    let mut decoder = VisionDecoder::new(user_id);
    let mut encoder = VisionEncoder::new(user_id).map_err(VisionSessionError::VisionEncode)?;

    let response_header = [VERSION, 0];
    let preamble = encoder
        .plan(0, VisionCommand::Continue, true)
        .map_err(VisionSessionError::VisionEncode)?;
    let preamble_len = response_header
        .len()
        .checked_add(preamble.wire_len())
        .ok_or(VisionSessionError::AllocationFailed)?;
    client_writer
        .write_assembled(
            preamble_len,
            |destination| {
                let Some((header, frame)) = destination.split_at_mut_checked(response_header.len())
                else {
                    return;
                };
                header.copy_from_slice(&response_header);
                encoder.assemble(&preamble, &[], frame);
            },
            timeout,
        )
        .await
        .map_err(VisionSessionError::Tls)?;
    encoder.commit(&preamble);

    let mut vision_plaintext = Vec::new();
    if !prefetched_plaintext.is_empty() {
        let mode = decoder
            .decode_append(&prefetched_plaintext, &mut vision_plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        if mode == VisionMode::Direct {
            return Err(VisionSessionError::Xudp(
                XudpSessionError::UnexpectedVisionDirect,
            ));
        }
    }
    drop(prefetched_plaintext);

    let mut packets = drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;
    let mut association = None::<XudpDirectAssociation<'_>>;
    let globals = process_xudp_global_map();
    let mut uplink_bytes = 0_u64;
    let mut downlink_bytes = 0_u64;

    loop {
        for packet in packets.drain(..) {
            // First New: LINE already authorized transfer; dial the sealed
            // (DNS-resolved) initial destination. Later Keep rewrites must pass
            // the sealed policy snapshot (ordered rules + default outbound).
            let authorized = if association.is_none() {
                if packet.destination.is_none() {
                    return Err(VisionSessionError::Xudp(
                        XudpSessionError::MissingNewDestination,
                    ));
                }
                Some(policy.initial_destination().clone())
            } else if let Some(dest) = packet.destination.as_ref() {
                policy
                    .authorize_udp_destination(dest)
                    .map_err(|_| VisionSessionError::Xudp(XudpSessionError::UnauthorizedRewrite))?;
                Some(dest.clone())
            } else {
                None
            };
            if association.is_none() {
                let bind_dest = authorized.clone().expect("first New sets authorized");
                let now = std::time::Instant::now();
                association = Some(
                    XudpDirectAssociation::open(
                        &bind_dest,
                        packet.global_id,
                        *user_id.as_bytes(),
                        globals,
                        now,
                        udp_bind_ip,
                    )
                    .await
                    .map_err(VisionSessionError::Xudp)?,
                );
            }
            if let Some(assoc) = association.as_mut() {
                let now = std::time::Instant::now();
                assoc
                    .handle_uplink_packet(&packet, authorized.as_ref(), now)
                    .await
                    .map_err(VisionSessionError::Xudp)?;
                uplink_bytes = uplink_bytes.saturating_add(packet.payload.len() as u64);
            }
        }
        if association.is_some() {
            break;
        }
        let record = client_reader
            .read_application(timeout)
            .await
            .map_err(VisionSessionError::Tls)?;
        if record.is_empty() {
            continue;
        }
        let (mode, payload) = decoder
            .decode_borrowed_append(record.plaintext(), &mut vision_plaintext)
            .map_err(VisionSessionError::VisionDecode)?;
        if let VisionPayload::Borrowed(content) = payload {
            vision_plaintext.extend_from_slice(content);
        }
        if mode == VisionMode::Direct {
            return Err(VisionSessionError::Xudp(
                XudpSessionError::UnexpectedVisionDirect,
            ));
        }
        packets = drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;
    }

    let mut assoc = association.expect("opened above");
    let mut udp_buf = vec![0_u8; 64 * 1024];
    let mut downlink_frame = Vec::new();
    let mut vision_frame = Vec::new();
    let idle = XUDP_ASSOCIATION_IDLE;

    loop {
        tokio::select! {
            biased;
            record = client_reader.read_application(timeout) => {
                match record {
                    Ok(record) => {
                        if record.is_empty() {
                            continue;
                        }
                        let (mode, payload) = decoder
                            .decode_borrowed_append(record.plaintext(), &mut vision_plaintext)
                            .map_err(VisionSessionError::VisionDecode)?;
                        if let VisionPayload::Borrowed(content) = payload {
                            vision_plaintext.extend_from_slice(content);
                        }
                        if mode == VisionMode::Direct {
                            break;
                        }
                        let more = drain_xudp_frames(&mut vision_plaintext)
                            .map_err(VisionSessionError::Xudp)?;
                        let now = std::time::Instant::now();
                        for packet in more {
                            let authorized = if let Some(dest) = packet.destination.as_ref() {
                                policy
                                    .authorize_udp_destination(dest)
                                    .map_err(|_| {
                                        VisionSessionError::Xudp(
                                            XudpSessionError::UnauthorizedRewrite,
                                        )
                                    })?;
                                Some(dest.clone())
                            } else {
                                None
                            };
                            assoc
                                .handle_uplink_packet(&packet, authorized.as_ref(), now)
                                .await
                                .map_err(VisionSessionError::Xudp)?;
                            uplink_bytes =
                                uplink_bytes.saturating_add(packet.payload.len() as u64);
                        }
                        activity.progress();
                    }
                    Err(TlsApplicationIoError::PeerAlert { description: 0, .. }) => break,
                    Err(error) => return Err(VisionSessionError::Tls(error)),
                }
            }
            recv = assoc.recv_downlink_frame(&mut udp_buf, &mut downlink_frame, std::time::Instant::now()) => {
                let _ = recv.map_err(VisionSessionError::Xudp)?;
                encoder
                    .encode(
                        &downlink_frame,
                        VisionCommand::Continue,
                        false,
                        &mut vision_frame,
                    )
                    .map_err(VisionSessionError::VisionEncode)?;
                client_writer
                    .write_application(&vision_frame, timeout)
                    .await
                    .map_err(VisionSessionError::Tls)?;
                downlink_bytes =
                    downlink_bytes.saturating_add(downlink_frame.len() as u64);
                activity.progress();
            }
            () = activity.expired(idle) => {
                break;
            }
        }
    }

    assoc.close(std::time::Instant::now());
    let _ = client_writer.shutdown(timeout).await;
    Ok(VisionRelayStats {
        uplink_bytes,
        downlink_bytes,
        ..VisionRelayStats::default()
    })
}

/// Landward owner for one XUDP association (Direct local UDP or NXR carrier).
pub(super) enum XudpLandwardAssociation<'a> {
    Direct(XudpDirectAssociation<'a>),
    Nxr(XudpNxrAssociation<'a>),
}

impl XudpLandwardAssociation<'_> {
    pub(super) const fn capability(&self) -> XudpEgressCapability {
        match self {
            Self::Direct(_) => XudpEgressCapability::Direct,
            Self::Nxr(_) => XudpEgressCapability::Nxr,
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
        }
    }

    pub(super) async fn close(self, now: std::time::Instant) {
        match self {
            Self::Direct(assoc) => assoc.close(now),
            Self::Nxr(assoc) => assoc.close(now).await,
        }
    }
}
