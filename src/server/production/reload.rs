//! The line between what a running process can change and what it cannot.
//!
//! Cold is structural: which sockets exist, how this process dials, which
//! resolver it installed, and the resource posture every pool was sized
//! against. Everything else — users, routing, outbounds, log level, assets,
//! landing keys — is hot, and a reload simply publishes a new generation.
//!
//! The comparison is deliberately a *shape* comparison, not a field-by-field
//! diff of numbers. Since the effective policy stopped living inside the
//! configuration there is nothing left for the two to disagree about: it is
//! derived once at startup and reused, so a reload compares operator input
//! against operator input.

use std::{collections::HashMap, net::SocketAddr};

use crate::{
    config::{NodeConfig, node::landing::LandingProtocol, node::listener::ListenFamily},
    runtime::{machine::MachineReport, policy::resolve_resource_mode},
};

use super::{error::RuntimeUpdateError, snapshot::RuntimeSnapshot};

/// Rejects a reload that would change something only a restart can change.
///
/// The cold set is structural: which sockets exist, how this process dials,
/// which resolver it installed, and the resource posture the pools were sized
/// against. Everything else — users, routing, outbounds, log level, assets —
/// is hot, and a new generation simply replaces the old one.
///
/// The effective policy is *not* recompared here. It is derived once at
/// startup and stored in the store; a reload reuses it rather than deriving
/// again, so there is nothing for the two to disagree about. That is a direct
/// consequence of the policy no longer living inside the configuration: when
/// the two were the same value, a reload had to re-derive and re-compare to
/// tell an operator edit apart from a machine-view drift.
pub(super) fn ensure_hot_compatible(
    current: &RuntimeSnapshot,
    candidate: NodeConfig,
) -> Result<NodeConfig, RuntimeUpdateError> {
    if listener_topology(&candidate) != listener_topology(&current.node) {
        return Err(RuntimeUpdateError::ListenerTopologyChanged);
    }
    if candidate.network() != current.node.network() {
        return Err(RuntimeUpdateError::NetworkDialPolicyChanged);
    }
    // The shared DNS resolver is a process-lifetime first-wins install, so a
    // reload can never swap it; reject DNS drift instead of silently keeping
    // the old resolver.
    if candidate.dns() != current.node.dns() {
        return Err(RuntimeUpdateError::DnsPolicyChanged);
    }
    // The runtime posture is cold: the descriptor budget, the memory monitor,
    // and every admission ceiling were sized against it before the first
    // listener bound. The resource mode compares resolved values against one
    // freshly detected machine view, so identical configurations never
    // disagree.
    let machine = MachineReport::detect();
    let current_runtime = current.node.runtime();
    let candidate_runtime = candidate.runtime();
    let posture_matches = resolve_resource_mode(current_runtime.profile(), &machine)
        == resolve_resource_mode(candidate_runtime.profile(), &machine)
        && current_runtime.profile() == candidate_runtime.profile()
        && current_runtime.tuning() == candidate_runtime.tuning()
        && current_runtime.objective() == candidate_runtime.objective()
        && current_runtime.status_file == candidate_runtime.status_file
        && current_runtime.limits() == candidate_runtime.limits();
    if !posture_matches {
        return Err(RuntimeUpdateError::ResourceModeChanged);
    }
    Ok(candidate)
}

/// What a bound socket speaks, for the reload topology comparison.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerRole {
    /// Public VLESS + REALITY + Vision.
    Entry,
    /// Internal NXR.
    Nxr,
    /// Internal Handoff.
    Handoff,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ListenerTopology {
    protocol: ListenerRole,
    mode: ListenFamily,
}

fn listener_topology(node: &NodeConfig) -> HashMap<SocketAddr, ListenerTopology> {
    let protocol = match node {
        NodeConfig::Entry(_) => ListenerRole::Entry,
        NodeConfig::Landing(landing) => match landing.landing {
            LandingProtocol::Nxr(_) => ListenerRole::Nxr,
            LandingProtocol::Handoff(_) => ListenerRole::Handoff,
        },
    };
    node.listeners()
        .iter()
        .flat_map(|listener| {
            let topology = ListenerTopology {
                protocol,
                mode: listener.family(),
            };
            listener
                .bind_addresses()
                .into_iter()
                .map(move |address| (address, topology))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use tokio::io::AsyncWriteExt as _;
    use tokio::net::TcpListener;

    use crate::{
        config::{NodeConfig, ValidatedConfig, node::fixture},
        protocol::vless::{Address, Destination},
        server::production::{
            ProductionServer, RuntimeUpdateError,
            fixture::{cold_variant, entry_config, unused_loopback_port},
            snapshot::ConnectionHandler,
        },
    };

    #[test]
    fn rejected_hot_update_keeps_last_good_runtime() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let previous = server.runtime.load();
        let replacement = entry_config(9443).into_node();

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ListenerTopologyChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn listener_topology_and_dial_policy_changes_require_restart() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");

        // A family change expands to different sockets, so the topology moves.
        let listener_change = fixture::validated(&fixture::entry_without_routing(
            r#""listeners": [{ "port": 8443 }],
  "routing": { "default": "direct" }"#,
        ))
        .into_node();
        assert!(matches!(
            server.runtime.publish(listener_change),
            Err(RuntimeUpdateError::ListenerTopologyChanged)
        ));

        assert!(matches!(
            server.runtime.publish(cold_variant(8443)),
            Err(RuntimeUpdateError::NetworkDialPolicyChanged)
        ));

        let dns_change = fixture::validated(&fixture::entry_without_routing(
            r#""listeners": [{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }],
  "routing": { "default": "direct" },
  "dns": { "timeoutMs": 6000 }"#,
        ))
        .into_node();
        assert!(matches!(
            server.runtime.publish(dns_change),
            Err(RuntimeUpdateError::DnsPolicyChanged)
        ));
    }

    const ROTATION_PSK_A: [u8; 32] = [0x5a; 32];
    const ROTATION_PSK_B: [u8; 32] = [0x5b; 32];
    const ROTATION_SECRET_A: [u8; 32] = [0x77; 32];
    const ROTATION_SECRET_B: [u8; 32] = [0x78; 32];

    /// A Handoff landing node with an explicit rotation window.
    ///
    /// This is a landing node on its own: entry and landing are separate
    /// roles, so a rotation test configures the node that holds the keys.
    fn rotation_config(
        port: u16,
        active_psk: [u8; 32],
        active_secret: [u8; 32],
        previous_psks: &[[u8; 32]],
        previous_secrets: &[[u8; 32]],
    ) -> ValidatedConfig {
        let encode = |bytes: &[u8; 32]| BASE64_URL_SAFE_NO_PAD.encode(bytes);
        let list = |keys: &[[u8; 32]]| {
            if keys.is_empty() {
                String::new()
            } else {
                let values: Vec<String> = keys
                    .iter()
                    .map(|key| format!("\"{}\"", encode(key)))
                    .collect();
                format!("[{}]", values.join(","))
            }
        };
        let previous_psk_field = if previous_psks.is_empty() {
            String::new()
        } else {
            format!(r#","previousPsks":{}"#, list(previous_psks))
        };
        let previous_secret_field = if previous_secrets.is_empty() {
            String::new()
        } else {
            format!(r#","previousPrivateKeys":{}"#, list(previous_secrets))
        };
        fixture::validated(&format!(
            r#"{{
  "role": "landing",
  "listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "landing": {{ "protocol": "handoff",
                "psk": "{}",
                "privateKey": "{}",
                "authenticationTimeoutMs": 1000,
                "connectTimeoutMs": 1000{previous_psk_field}{previous_secret_field} }}
}}"#,
            encode(&active_psk),
            encode(&active_secret)
        ))
    }

    /// Rotates only the landing's key material, keeping the listener topology
    /// — and therefore hot reload compatibility — intact.
    fn rotated_config(
        base: &ValidatedConfig,
        active_psk: [u8; 32],
        active_secret: [u8; 32],
        previous_psks: &[[u8; 32]],
        previous_secrets: &[[u8; 32]],
    ) -> NodeConfig {
        rotation_config(
            base.node().listeners()[0].port,
            active_psk,
            active_secret,
            previous_psks,
            previous_secrets,
        )
        .into_node()
    }

    fn handoff_handler(
        server: &ProductionServer,
        address: &SocketAddr,
    ) -> crate::server::handoff::HandoffLandingHandler {
        let snapshot = server.runtime.load();
        let ConnectionHandler::Handoff(handler) = &snapshot
            .connections
            .get(address)
            .expect("the handoff listener must exist")
            .handler
        else {
            panic!("the listener must be a handoff landing");
        };
        handler.clone()
    }

    /// Seals a fresh transfer (fresh nonce) toward the discard port: when the
    /// landing authenticates it, the dial fails — proving every
    /// authentication step passed without standing up a destination.
    fn rotation_message(psk: [u8; 32], landing_secret: [u8; 32]) -> Vec<u8> {
        use crate::protocol::{
            handoff::{ContinuationState, HandoffPsk, seal_transfer},
            reality::tls13::{CipherSuite, TrafficKeys},
        };
        let landing_public =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(landing_secret));
        let state = ContinuationState::new(
            CipherSuite::ChaCha20Poly1305Sha256,
            TrafficKeys::from_raw_parts(&[0x11; 32], [0x21; 12]).expect("client keys"),
            1,
            TrafficKeys::from_raw_parts(&[0x12; 32], [0x22; 12]).expect("server keys"),
            0,
            [0x33; 16],
            Destination::new(Address::Ipv4(Ipv4Addr::LOCALHOST), 9),
            Vec::new(),
            Vec::new(),
        )
        .expect("test state must be valid");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock must be valid")
            .as_secs();
        let mut message = Vec::new();
        seal_transfer(
            &state,
            &HandoffPsk::new(psk),
            &landing_public,
            [0x44; 32],
            now,
            &mut message,
        )
        .expect("test state must seal");
        message
    }

    async fn deliver(
        handler: &crate::server::handoff::HandoffLandingHandler,
        message: &[u8],
    ) -> crate::server::handoff::HandoffLandingError {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("peer listener must bind");
        let address = listener.local_addr().expect("peer address must exist");
        let mut peer = tokio::net::TcpStream::connect(address)
            .await
            .expect("peer must connect");
        let (stream, _) = listener.accept().await.expect("listener must accept");
        peer.write_all(message).await.expect("message must write");
        let result = handler.handle(stream).await;
        drop(peer);
        result.expect_err("a transfer toward the discard port never relays")
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handoff_reload_rotates_keys_without_dropping_in_window_transfers() {
        use crate::protocol::handoff::HandoffError;
        use crate::server::handoff::HandoffLandingError;

        let port = unused_loopback_port();
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let base = rotation_config(port, ROTATION_PSK_A, ROTATION_SECRET_A, &[], &[]);
        let server =
            ProductionServer::from_config(base.clone()).expect("generation 0 must compile");

        // Generation 0: only the original pair is accepted.
        let handler = handoff_handler(&server, &address);
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_A, ROTATION_SECRET_A)
                )
                .await,
                HandoffLandingError::Destination(_)
            ),
            "the active pair must authenticate before rotation"
        );
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_B, ROTATION_SECRET_B)
                )
                .await,
                HandoffLandingError::Protocol(HandoffError::Authentication)
            ),
            "the next pair must fail before the window opens"
        );

        // Reload: the new pair becomes active, the retired pair stays
        // accepted inside the bounded window. The listener address and the
        // replay cache carry over untouched.
        server
            .runtime
            .publish(rotated_config(
                &base,
                ROTATION_PSK_B,
                ROTATION_SECRET_B,
                &[ROTATION_PSK_A],
                &[ROTATION_SECRET_A],
            ))
            .expect("a key rotation must be hot-compatible");
        let handler = handoff_handler(&server, &address);
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_B, ROTATION_SECRET_B)
                )
                .await,
                HandoffLandingError::Destination(_)
            ),
            "senders already on the new pair must land"
        );
        let old_pair_message = rotation_message(ROTATION_PSK_A, ROTATION_SECRET_A);
        assert!(
            matches!(
                deliver(&handler, &old_pair_message).await,
                HandoffLandingError::Destination(_)
            ),
            "senders still on the retired pair must land during the window"
        );
        assert!(
            matches!(
                deliver(&handler, &old_pair_message).await,
                HandoffLandingError::Protocol(HandoffError::Replay)
            ),
            "the retained replay cache must reject a redelivery across the reload"
        );

        // Reload again: the retired keys are dropped and the window closes.
        server
            .runtime
            .publish(rotated_config(
                &base,
                ROTATION_PSK_B,
                ROTATION_SECRET_B,
                &[],
                &[],
            ))
            .expect("dropping retired keys must be hot-compatible");
        let handler = handoff_handler(&server, &address);
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_A, ROTATION_SECRET_A)
                )
                .await,
                HandoffLandingError::Protocol(HandoffError::Authentication)
            ),
            "the retired pair must fail closed once dropped"
        );
        assert!(
            matches!(
                deliver(
                    &handler,
                    &rotation_message(ROTATION_PSK_B, ROTATION_SECRET_B)
                )
                .await,
                HandoffLandingError::Destination(_)
            ),
            "the active pair must keep landing after the window closes"
        );
    }

    #[test]
    fn a_pinned_limit_change_requires_restart() {
        // Admission ceilings, the direct-dial barrier, and the warm pools are
        // sized once, before the first listener binds. Everything they derive
        // from is therefore cold — and since one channel now carries every
        // pin, one comparison covers all of them.
        let pinned = |port: u16, connections: u32| {
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "limits": {{ "maxConnections": {connections} }} }}"#
            )))
        };
        let server =
            ProductionServer::from_config(pinned(8443, 4_096)).expect("server must compile");
        let previous = server.runtime.load();

        assert!(matches!(
            server.runtime.publish(pinned(8443, 8_192).into_node()),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn profile_change_requires_restart() {
        let posture = |port: u16, profile: &str| {
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "profile": "{profile}" }}"#
            )))
        };
        let server =
            ProductionServer::from_config(posture(8443, "shared")).expect("server must compile");
        let previous = server.runtime.load();

        assert!(matches!(
            server
                .runtime
                .publish(posture(8443, "dedicated").into_node()),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn tuning_mode_drift_requires_restart() {
        let tuned = |port: u16, tuning: Option<&str>| {
            let section = tuning.map_or(String::new(), |mode| {
                format!(r#","runtime": {{ "tuning": "{mode}", "statusFile": "/run/rr.json" }}"#)
            });
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }}{section}"#
            )))
        };
        let server = ProductionServer::from_config(tuned(8443, Some("adaptive")))
            .expect("server must compile");
        let previous = server.runtime.load();

        // An omitted tuning mode resolves to `startup`, which builds no
        // controller: the two produce different runtimes, so a reload rejects.
        assert!(matches!(
            server.runtime.publish(tuned(8443, None).into_node()),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn status_file_drift_requires_restart() {
        let with_status = |path: &str| {
            fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "tuning": "adaptive", "statusFile": "{path}" }}"#
            )))
        };
        let server = ProductionServer::from_config(with_status("/tmp/rust-reality-a.json"))
            .expect("server must compile");
        let previous = server.runtime.load();
        let replacement = with_status("/tmp/rust-reality-b.json").into_node();

        assert!(matches!(
            server.runtime.publish(replacement),
            Err(RuntimeUpdateError::ResourceModeChanged)
        ));
        assert!(Arc::ptr_eq(&previous, &server.runtime.load()));
    }

    #[test]
    fn an_unchanged_startup_tuned_config_reloads_cleanly() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        assert!(server.runtime.policy.governor.max_connections > 0);
        server
            .runtime
            .publish(entry_config(8443).into_node())
            .expect("the same startup-tuned configuration must reload");
    }
}
