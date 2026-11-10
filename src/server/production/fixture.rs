//! Configurations the tests in this subsystem are written against.
//!
//! There is no whole-config generator in the binary any more, so a test that
//! needs a server needs a *configuration* — composing one is exactly what an
//! operator does. Every fixture here is the smallest file that exercises its
//! case, and the differences between them are the point: `entry_config` and
//! `with_extra_outbound` differ by one hot field, `entry_config` and
//! `cold_variant` by one cold field.

use std::{io, sync::Arc};

use crate::config::{NodeConfig, ValidatedConfig, node::fixture};

use super::snapshot::{ConnectionHandler, ConnectionRuntime, RuntimeSnapshot};

/// A valid entry node bound to one loopback port.
pub(super) fn entry_config(port: u16) -> ValidatedConfig {
    fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }}"#
    )))
}

/// A hot-reloadable variant of the same node: one extra routing rule,
/// which changes nothing structural.
pub(super) fn with_extra_rule(port: u16, label: &str) -> ValidatedConfig {
    fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct",
    "rules": [{{ "name": "{label}", "ip": ["10.0.0.0/8"], "outbound": "block" }}] }}"#
    )))
}

/// The same node with one declared outbound added: a hot change.
pub(super) fn with_extra_outbound(port: u16, name: &str) -> NodeConfig {
    fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "outbounds": {{ "{name}": {{ "type": "socks5", "address": "10.0.0.9", "port": 1080,
                              "warmTcp": false }} }},
  "routing": {{ "default": "direct" }}"#
    )))
    .into_node()
}

/// The same node with a different dial policy: a cold change a reload
/// must refuse, because the process-wide dial policy is fixed at startup.
pub(super) fn cold_variant(port: u16) -> NodeConfig {
    fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "network": {{ "ip": "preferIpv6" }}"#
    )))
    .into_node()
}

/// A node whose admission ceilings are pinned as low as validation allows,
/// so a test can exhaust them in a few connections.
///
/// Only the two ceilings an operator can pin are stated; the rest derive,
/// which is the point of the reload tests that use this.
pub(super) fn tiny_ceiling_config() -> (ReservedLoopbackPort, ValidatedConfig) {
    let reserved = unused_loopback_port();
    let config = fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "limits": {{ "maxConnections": 2, "maxHandshakes": 2 }} }}"#,
        reserved.port()
    )));
    (reserved, config)
}

/// A loopback TCP port that stays reserved until the holder is released.
///
/// The previous helper bound `127.0.0.1:0` and immediately dropped the
/// listener, so a later `bind(0)` — including the same test's target
/// socket — could take that port. Packages 42340268763 attempt 1 then
/// failed with `NXR\x01` on the raw target versus `ping`. Keep this
/// reservation alive until every other ephemeral bind in the test has
/// finished, and release it only immediately before the server listens.
#[must_use = "dropping the reservation frees the port; keep it until the server binds"]
pub(super) struct ReservedLoopbackPort {
    listener: Option<std::net::TcpListener>,
    port: u16,
}

impl ReservedLoopbackPort {
    pub(super) fn port(&self) -> u16 {
        self.port
    }

    /// Drop the OS bind so this process can listen on the port.
    pub(super) fn release(mut self) -> u16 {
        let _ = self.listener.take();
        self.port
    }
}

pub(super) fn unused_loopback_port() -> ReservedLoopbackPort {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error: io::Error| panic!("reserve loopback port: {error}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|error: io::Error| panic!("reserved loopback address: {error}"))
        .port();
    ReservedLoopbackPort {
        listener: Some(listener),
        port,
    }
}

#[cfg(test)]
mod reservation_tests {
    use super::unused_loopback_port;

    #[test]
    fn holding_a_reserved_port_prevents_an_ephemeral_bind_from_taking_it() {
        let reserved = unused_loopback_port();
        assert!(
            std::net::TcpListener::bind(("127.0.0.1", reserved.port())).is_err(),
            "the reserved port must stay exclusive while held"
        );
        let other = std::net::TcpListener::bind("127.0.0.1:0").expect("another ephemeral port");
        assert_ne!(
            other.local_addr().expect("other address").port(),
            reserved.port(),
            "bind(0) must not take a held reservation"
        );
        let port = reserved.release();
        std::net::TcpListener::bind(("127.0.0.1", port))
            .expect("the released port must be bindable again");
    }
}

/// Returns the single listener runtime of a snapshot.
pub(super) fn only_listener(snapshot: &RuntimeSnapshot) -> Arc<ConnectionRuntime> {
    let mut listeners = snapshot.connections.values();
    let state = listeners
        .next()
        .expect("the fixture declares one listener")
        .clone();
    assert!(
        listeners.next().is_none(),
        "this test assumes a single listener"
    );
    state
}

/// Resolves the outbound table a snapshot's listener actually compiled.
///
/// Reaching through the handler rather than the config is the point: this is
/// the table a live connection would consult, so a crossing between
/// generations would be visible here and nowhere else.
pub(super) fn outbounds_of(
    state: &ConnectionRuntime,
) -> &crate::server::outbound::OutboundRegistry {
    match &state.handler {
        ConnectionHandler::Public { vision, .. } => vision.outbounds(),
        ConnectionHandler::Nxr(_) | ConnectionHandler::Handoff(_) => {
            panic!("the fixture listener must be a public VLESS listener")
        }
    }
}
