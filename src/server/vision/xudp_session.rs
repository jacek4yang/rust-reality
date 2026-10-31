//! Vision XUDP session path (authorize + handle_xudp).
//!
//! Internal to [`crate::server::vision`]: owns XUDP destination authorization
//! and the Vision-framed XUDP association loop. Behavior-preserving
//! modularization only — no wire, crypto, or trust changes.

use std::{net::IpAddr, ops::Range, sync::Arc};

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::io_activity::SessionActivity;
use crate::protocol::reality::tls13::{
    TlsApplicationIoError, TlsApplicationReader, TlsApplicationWriter,
};
use crate::protocol::vless::{
    UserId, VERSION, VisionCommand, VisionDecoder, VisionEncoder, VisionMode, VisionPayload,
};
use crate::server::outbound::SessionOutboundOutcome;
use crate::server::xudp::{
    XUDP_ASSOCIATION_IDLE, XudpDirectAssociation, XudpEgressCapability, XudpNxrAssociation,
    XudpSessionError, authorize_xudp_egress, drain_xudp_frames, process_xudp_global_map,
    require_direct_xudp_landward, require_handoff_xudp_landward, require_nxr_xudp_landward,
};

use super::VisionHandler;
use super::error::VisionSessionError;
use super::handoff_resume::XudpLandwardAssociation;
use super::stats::VisionRelayStats;

impl VisionHandler {
    /// Authorize an XUDP New/Keep destination: canonical routing, DNS, egress class.
    ///
    /// Keep rewrites MUST call this again; a prior decision must not be inherited
    /// when the new destination routes to Block or another outbound. Returns a
    /// distinct [`XudpEgressCapability`] (Direct / NXR / Handoff), the resolved
    /// destination, and the outbound tag — never remaps NXR/Handoff to Direct
    /// (ADR 0060).
    pub(crate) async fn authorize_xudp_destination(
        &self,
        user_id: UserId,
        inbound_tag: &str,
        dest: &crate::protocol::vless::Destination,
    ) -> Result<
        (
            XudpEgressCapability,
            crate::protocol::vless::Destination,
            String,
        ),
        VisionSessionError,
    > {
        let route = self
            .routing
            .select_with_dns(
                user_id,
                inbound_tag,
                dest,
                self.dns_strategy,
                self.dns_timeout,
            )
            .await
            .map_err(VisionSessionError::Route)?;
        let outbound_tag = route.decision().outbound().to_owned();
        let capability = authorize_xudp_egress(self.outbounds.xudp_route_class(&outbound_tag))
            .map_err(|error| VisionSessionError::Xudp(XudpSessionError::Outbound(error)))?;
        let resolved = if let Some(ip) = route.resolved_ips().first().copied() {
            match ip {
                IpAddr::V4(v4) => crate::protocol::vless::Destination::new(
                    crate::protocol::vless::Address::Ipv4(v4),
                    dest.port(),
                ),
                IpAddr::V6(v6) => crate::protocol::vless::Destination::new(
                    crate::protocol::vless::Address::Ipv6(v6),
                    dest.port(),
                ),
            }
        } else {
            dest.clone()
        };
        Ok((capability, resolved, outbound_tag))
    }

    /// Serves one REALITY-authenticated Vision **XUDP** (Mux) session.
    ///
    /// XUDP frames ride inside Vision padding. Routing may authorize Direct or
    /// NXR (ADR 0060 Option A framed carrier). Handoff transfers TLS ownership
    /// to LANDING before any client-visible Vision response (ADR 0060 Option B);
    /// LINE never decrypts that session again after a successful transfer.
    /// Keep rewrites re-authorize; capability changes and Block fail closed
    /// with zero landward packets (no silent Direct fallback).
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit XUDP session boundary fields"
    )]
    pub(super) async fn handle_xudp(
        &self,
        mut client_reader: TlsApplicationReader<OwnedReadHalf>,
        mut client_writer: TlsApplicationWriter<OwnedWriteHalf>,
        inbound_tag: &str,
        user_id: UserId,
        request_buffer: Vec<u8>,
        prefetched: Range<usize>,
        client_random: [u8; 32],
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let activity = Arc::new(SessionActivity::default());
        client_writer.set_activity(Arc::clone(&activity));

        let mut decoder = VisionDecoder::new(user_id);
        let mut encoder = VisionEncoder::new(user_id).map_err(VisionSessionError::VisionEncode)?;

        // Delay the Vision response until egress is known. For Handoff, LANDING
        // writes the first client-visible success after accepting the transfer.
        let response_header = [VERSION, 0];
        let mut response_sent = false;

        let mut vision_plaintext = Vec::new();
        // Vision wire bytes observed on LINE before transfer — LANDING re-decodes.
        let mut vision_wire_for_transfer = Vec::new();
        if let Some(initial) = request_buffer.get(prefetched)
            && !initial.is_empty()
        {
            vision_wire_for_transfer.extend_from_slice(initial);
            let mode = decoder
                .decode_append(initial, &mut vision_plaintext)
                .map_err(VisionSessionError::VisionDecode)?;
            if mode == VisionMode::Direct {
                return Err(VisionSessionError::Xudp(
                    XudpSessionError::UnexpectedVisionDirect,
                ));
            }
        }
        drop(request_buffer);

        let mut packets =
            drain_xudp_frames(&mut vision_plaintext).map_err(VisionSessionError::Xudp)?;

        let mut association = None::<XudpLandwardAssociation<'_>>;
        let globals = process_xudp_global_map();
        let mut uplink_bytes = 0_u64;
        let mut downlink_bytes = 0_u64;

        loop {
            for packet in packets.drain(..) {
                let authorized = if let Some(dest) = packet.destination.as_ref() {
                    let (capability, resolved, outbound_tag) = self
                        .authorize_xudp_destination(user_id, inbound_tag, dest)
                        .await?;
                    Some((capability, resolved, outbound_tag, dest.clone()))
                } else {
                    None
                };
                if association.is_none() {
                    let (capability, bind_dest, outbound_tag, route_dest) =
                        authorized.clone().ok_or(VisionSessionError::Xudp(
                            XudpSessionError::MissingNewDestination,
                        ))?;
                    if capability == XudpEgressCapability::Handoff {
                        // LINE does not open landward UDP; transfer then splice.
                        // Seal the DNS-resolved destination so LANDING can bind
                        // UDP without re-resolving (domain addresses fail closed).
                        let outcome = self
                            .outbounds
                            .connect_session_resolved(&outbound_tag, &bind_dest, &[])
                            .await
                            .map_err(VisionSessionError::Outbound)?;
                        let SessionOutboundOutcome::Handoff(line) = outcome else {
                            return Err(VisionSessionError::Xudp(XudpSessionError::Outbound(
                                crate::server::xudp::XudpOutboundUnsupported::Handoff,
                            )));
                        };
                        let _ = route_dest;
                        // No client-visible success before LANDING accepts.
                        return self
                            .relay_via_handoff_xudp(
                                &line,
                                client_reader,
                                client_writer,
                                user_id,
                                bind_dest,
                                inbound_tag,
                                &outbound_tag,
                                vision_wire_for_transfer,
                                client_random,
                            )
                            .await;
                    }
                    if !response_sent {
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
                                    let Some((header, frame)) =
                                        destination.split_at_mut_checked(response_header.len())
                                    else {
                                        return;
                                    };
                                    header.copy_from_slice(&response_header);
                                    encoder.assemble(&preamble, &[], frame);
                                },
                                self.io_timeout,
                            )
                            .await
                            .map_err(VisionSessionError::Tls)?;
                        encoder.commit(&preamble);
                        response_sent = true;
                    }
                    let now = std::time::Instant::now();
                    let assoc = match capability {
                        XudpEgressCapability::Direct => {
                            require_direct_xudp_landward(capability).map_err(|error| {
                                VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                            })?;
                            XudpLandwardAssociation::Direct(
                                XudpDirectAssociation::open(
                                    &bind_dest,
                                    packet.global_id,
                                    *user_id.as_bytes(),
                                    globals,
                                    now,
                                    None,
                                )
                                .await
                                .map_err(VisionSessionError::Xudp)?,
                            )
                        }
                        XudpEgressCapability::Nxr => {
                            require_nxr_xudp_landward(capability).map_err(|error| {
                                VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                            })?;
                            XudpLandwardAssociation::Nxr(
                                XudpNxrAssociation::open(
                                    &self.outbounds,
                                    &outbound_tag,
                                    &bind_dest,
                                    *user_id.as_bytes(),
                                    packet.global_id,
                                    globals,
                                    now,
                                )
                                .await
                                .map_err(VisionSessionError::Xudp)?,
                            )
                        }
                        XudpEgressCapability::Handoff => {
                            unreachable!("Handoff transfers above before landward open")
                        }
                    };
                    association = Some(assoc);
                }
                if let Some(assoc) = association.as_mut() {
                    let now = std::time::Instant::now();
                    let resolved = if let Some((capability, resolved, _, _)) = authorized.as_ref() {
                        if *capability != assoc.capability() {
                            return Err(VisionSessionError::Xudp(
                                XudpSessionError::EgressCapabilityChanged,
                            ));
                        }
                        match capability {
                            XudpEgressCapability::Direct => {
                                require_direct_xudp_landward(*capability).map_err(|error| {
                                    VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                                })?;
                            }
                            XudpEgressCapability::Nxr => {
                                require_nxr_xudp_landward(*capability).map_err(|error| {
                                    VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                                })?;
                            }
                            XudpEgressCapability::Handoff => {
                                require_handoff_xudp_landward(*capability).map_err(|error| {
                                    VisionSessionError::Xudp(XudpSessionError::Outbound(error))
                                })?;
                            }
                        }
                        Some(resolved.clone())
                    } else {
                        None
                    };
                    assoc
                        .handle_uplink_packet(&packet, resolved.as_ref(), now)
                        .await
                        .map_err(VisionSessionError::Xudp)?;
                    uplink_bytes = uplink_bytes.saturating_add(packet.payload.len() as u64);
                }
            }

            if association.is_some() {
                break;
            }

            let record = client_reader
                .read_application(self.request_timeout)
                .await
                .map_err(VisionSessionError::Tls)?;
            if record.is_empty() {
                continue;
            }
            vision_wire_for_transfer.extend_from_slice(record.plaintext());
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
                record = client_reader.read_application(self.io_timeout) => {
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
                                let resolved = if let Some(dest) = packet.destination.as_ref() {
                                    let (capability, resolved, _) = self
                                        .authorize_xudp_destination(
                                            user_id,
                                            inbound_tag,
                                            dest,
                                        )
                                        .await?;
                                    if capability != assoc.capability() {
                                        return Err(VisionSessionError::Xudp(
                                            XudpSessionError::EgressCapabilityChanged,
                                        ));
                                    }
                                    match capability {
                                        XudpEgressCapability::Direct => {
                                            require_direct_xudp_landward(capability).map_err(
                                                |error| {
                                                    VisionSessionError::Xudp(
                                                        XudpSessionError::Outbound(error),
                                                    )
                                                },
                                            )?;
                                        }
                                        XudpEgressCapability::Nxr => {
                                            require_nxr_xudp_landward(capability).map_err(
                                                |error| {
                                                    VisionSessionError::Xudp(
                                                        XudpSessionError::Outbound(error),
                                                    )
                                                },
                                            )?;
                                        }
                                        XudpEgressCapability::Handoff => {
                                            require_handoff_xudp_landward(capability).map_err(
                                                |error| {
                                                    VisionSessionError::Xudp(
                                                        XudpSessionError::Outbound(error),
                                                    )
                                                },
                                            )?;
                                        }
                                    }
                                    Some(resolved)
                                } else {
                                    None
                                };
                                assoc
                                    .handle_uplink_packet(&packet, resolved.as_ref(), now)
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
                        .write_application(&vision_frame, self.io_timeout)
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

        assoc.close(std::time::Instant::now()).await;
        let _ = client_writer.shutdown(self.io_timeout).await;
        Ok(VisionRelayStats {
            uplink_bytes,
            downlink_bytes,
            ..VisionRelayStats::default()
        })
    }
}
