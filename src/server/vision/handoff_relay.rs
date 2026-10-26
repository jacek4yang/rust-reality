//! Vision Handoff LINE→LANDING transfer relay helpers.
//!
//! Internal to [`crate::server::vision`]: owns TCP and XUDP handoff transfer
//! then raw/association relay against the landing socket. Behavior-preserving
//! modularization only — no wire, crypto, or trust changes.

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::protocol::handoff::{
    ContinuationState, HandoffError, HandoffPolicySnapshot, SessionKind,
};
use crate::protocol::reality::tls13::{TlsApplicationReader, TlsApplicationWriter};
use crate::protocol::vless::{Destination, UserId};
use crate::server::handoff::HandoffLineError;
use crate::server::xudp::XudpSessionError;
use crate::transport::RelayContext;

use super::VisionHandler;
use super::abort::SocketAbortGuard;
use super::error::VisionSessionError;
use super::handoff_resume::reunite_handoff_client;
use super::request::AcceptedVisionRequest;
use super::stats::VisionRelayStats;

impl VisionHandler {
    /// Transfers one boundary-session to a Handoff landing node, then relays
    /// the client socket against the handoff socket raw in both directions.
    ///
    /// The continuation carries both current traffic secrets and record
    /// sequences, any owed KeyUpdate response, the reader's read-ahead
    /// ciphertext, and the prefetched VLESS payload; afterwards this node
    /// never decrypts or frames the session again. Any failure — dial, seal,
    /// or write — leaves the abort guard armed, so the client socket is reset
    /// rather than half-closed and the session is never served locally with
    /// consumed state. A successful transfer always produces immediate
    /// downlink (an owed KeyUpdate response, otherwise the response header and
    /// opening Vision frame), while every rejection closes the connection
    /// silently; the first landing byte is therefore awaited with a bounded
    /// deadline before the relay starts, and its absence — close, stall, or
    /// non-TLS bytes — is classified as rejection while every descriptor is
    /// still open, so the armed guard resets the client socket instead of
    /// FIN-ing it and the sockets, permits, and pipes release immediately.
    /// The client halves are reunited before the probe so the abortive close
    /// is not preceded by `OwnedWriteHalf`'s shutdown-on-drop FIN.
    pub(super) async fn relay_via_handoff(
        &self,
        line: &crate::server::handoff::HandoffLine,
        client_reader: TlsApplicationReader<OwnedReadHalf>,
        client_writer: TlsApplicationWriter<OwnedWriteHalf>,
        request: AcceptedVisionRequest,
        client_random: [u8; 32],
        inbound_tag: &str,
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let AcceptedVisionRequest::Tcp {
            user_id,
            destination,
            buffer,
            prefetched,
        } = request
        else {
            return Err(VisionSessionError::Xudp(XudpSessionError::Outbound(
                crate::server::xudp::XudpOutboundUnsupported::Handoff,
            )));
        };
        let (pending, client_read_half, client_records) = client_reader.into_handoff_parts();
        let (client_write_half, server_records, key_update_response_pending) =
            client_writer.into_handoff_parts();
        // Phase one: the client socket is the only descriptor that exists, so
        // it is the only thing to reset. Its guard borrows the read half, so
        // the transfer below cannot consume or close the socket while the
        // guard could still fire.
        let (transferred, server_sequence) = {
            let mut client_abort = SocketAbortGuard::new(&client_read_half);
            let (suite, client_traffic_secret, client_sequence) = client_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let (_suite, server_traffic_secret, server_sequence) = server_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let prefetched = buffer.get(prefetched).unwrap_or_default().to_vec();
            let policy = HandoffPolicySnapshot::tcp_placeholder(destination.clone());
            let state = ContinuationState::new(
                suite,
                client_traffic_secret,
                client_sequence,
                server_traffic_secret,
                server_sequence,
                key_update_response_pending,
                SessionKind::Tcp,
                *user_id.as_bytes(),
                inbound_tag,
                destination,
                pending,
                prefetched,
                policy,
            )
            .map_err(HandoffLineError::Transfer)
            .map_err(VisionSessionError::HandoffLine)?;
            let transferred = line
                .transfer(self.relay.fd_budget(), &state, client_random)
                .await
                .map_err(VisionSessionError::HandoffLine)?;
            // The sealed continuation is on the wire; its generation secrets
            // must not live across the first-byte probe and session relay.
            drop(state);
            client_abort.disarm();
            (transferred, server_sequence)
        };
        // Declared before the stream so every error path closes the handoff
        // descriptor before its budget unit is released.
        let _fd_permit = transferred.1;
        let handoff_stream = transferred.0;
        // Reuniting consumes both client halves, so the landing descriptor —
        // which now exists and would otherwise leak a FIN — carries its own
        // guard across the only fallible step between the two phases.
        let client_stream =
            reunite_handoff_client(client_read_half, client_write_half, &handoff_stream)?;
        // Classify the silent protocol's only failure signal before any socket
        // moves into the relay: no TLS downlink byte within the configured
        // first-byte deadline means rejection. Both guards borrow their
        // sockets, so a rejection — or a cancellation inside the probe — resets
        // descriptors that are provably still open (SO_LINGER {on,0}); they
        // close as whole streams right after, delivering RST — never FIN — and
        // the session's descriptors, permits, and pipes are not held until the
        // idle timeout.
        let landed = {
            let mut landing_abort = SocketAbortGuard::new(&handoff_stream);
            let mut client_abort = SocketAbortGuard::new(&client_stream);
            let landed = crate::server::handoff::first_downlink_landed(
                &handoff_stream,
                line.first_byte_timeout(),
            )
            .await;
            if landed {
                // Ownership passes to the relay below, which owns abort
                // semantics for both sockets from here on.
                client_abort.disarm();
                landing_abort.disarm();
            }
            landed
        };
        if !landed {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        // The relay consumes both sockets: it aborts them itself on a
        // mid-transfer error, and on every return their descriptors are
        // already closed. No guard is armed here, so nothing can fire on what
        // another connection may have recycled those descriptor numbers into.
        let result = self
            .relay
            .relay_owned(
                client_stream,
                handoff_stream,
                // Both sockets carry the session's TLS records, whose own
                // close semantics LANDING and the client enforce; a teardown
                // reset from either side ends its direction like an EOF.
                RelayContext::owned()
                    .with_write_stall(self.io_timeout)
                    .with_source_reset_as_eof(),
            )
            .await;
        let outcome = result
            .map_err(HandoffLineError::Relay)
            .map_err(VisionSessionError::HandoffLine)?;
        // Backstop for the first-byte probe above: a completed relay that
        // moved zero downlink bytes still reads as a rejection.
        if outcome.outbound_to_inbound() == 0 {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        // The counts are raw ciphertext bytes moved by the splice, matching how
        // the Direct transition counts its raw phase.
        Ok(VisionRelayStats {
            uplink_bytes: outcome.inbound_to_outbound(),
            downlink_bytes: outcome.outbound_to_inbound(),
            relay_backend: Some(outcome.backend()),
            handoff_server_sequence: Some(server_sequence),
            pipe_capacity_downgraded: outcome.pipe_downgrade().is_some(),
            ..VisionRelayStats::default()
        })
    }

    /// Transfers one XUDP Vision session to a Handoff landing node.
    ///
    /// LINE never sends a client-visible Vision response; LANDING resumes TLS,
    /// writes the first success, owns UDP, and frames XUDP (ADR 0060). After a
    /// successful transfer this node only splices ciphertext.
    #[allow(
        clippy::too_many_arguments,
        reason = "explicit transfer boundary fields"
    )]
    pub(super) async fn relay_via_handoff_xudp(
        &self,
        line: &crate::server::handoff::HandoffLine,
        client_reader: TlsApplicationReader<OwnedReadHalf>,
        client_writer: TlsApplicationWriter<OwnedWriteHalf>,
        user_id: UserId,
        destination: Destination,
        inbound_tag: &str,
        outbound_tag: &str,
        prefetched_vision_wire: Vec<u8>,
        client_random: [u8; 32],
    ) -> Result<VisionRelayStats, VisionSessionError> {
        let (pending, client_read_half, client_records) = client_reader.into_handoff_parts();
        let (client_write_half, server_records, key_update_response_pending) =
            client_writer.into_handoff_parts();
        let (transferred, server_sequence) = {
            let mut client_abort = SocketAbortGuard::new(&client_read_half);
            let (suite, client_traffic_secret, client_sequence) = client_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let (_suite, server_traffic_secret, server_sequence) = server_records
                .into_exported_state()
                .map_err(|_| HandoffLineError::Transfer(HandoffError::State))
                .map_err(VisionSessionError::HandoffLine)?
                .into_parts();
            let policy =
                self.routing
                    .seal_handoff_xudp_policy(user_id, outbound_tag, destination.clone());
            let state = ContinuationState::new(
                suite,
                client_traffic_secret,
                client_sequence,
                server_traffic_secret,
                server_sequence,
                key_update_response_pending,
                SessionKind::Xudp,
                *user_id.as_bytes(),
                inbound_tag,
                destination,
                pending,
                prefetched_vision_wire,
                policy,
            )
            .map_err(HandoffLineError::Transfer)
            .map_err(VisionSessionError::HandoffLine)?;
            let transferred = line
                .transfer(self.relay.fd_budget(), &state, client_random)
                .await
                .map_err(VisionSessionError::HandoffLine)?;
            drop(state);
            client_abort.disarm();
            (transferred, server_sequence)
        };
        let _fd_permit = transferred.1;
        let handoff_stream = transferred.0;
        let client_stream =
            reunite_handoff_client(client_read_half, client_write_half, &handoff_stream)?;
        let landed = {
            let mut landing_abort = SocketAbortGuard::new(&handoff_stream);
            let mut client_abort = SocketAbortGuard::new(&client_stream);
            let landed = crate::server::handoff::first_downlink_landed(
                &handoff_stream,
                line.first_byte_timeout(),
            )
            .await;
            if landed {
                client_abort.disarm();
                landing_abort.disarm();
            }
            landed
        };
        if !landed {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        let result = self
            .relay
            .relay_owned(
                client_stream,
                handoff_stream,
                RelayContext::owned()
                    .with_write_stall(self.io_timeout)
                    .with_source_reset_as_eof(),
            )
            .await;
        let outcome = result
            .map_err(HandoffLineError::Relay)
            .map_err(VisionSessionError::HandoffLine)?;
        if outcome.outbound_to_inbound() == 0 {
            return Err(VisionSessionError::HandoffLine(
                HandoffLineError::LandingRejected,
            ));
        }
        Ok(VisionRelayStats {
            uplink_bytes: outcome.inbound_to_outbound(),
            downlink_bytes: outcome.outbound_to_inbound(),
            relay_backend: Some(outcome.backend()),
            handoff_server_sequence: Some(server_sequence),
            pipe_capacity_downgraded: outcome.pipe_downgrade().is_some(),
            ..VisionRelayStats::default()
        })
    }
}
