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
pub(super) fn tiny_ceiling_config() -> ValidatedConfig {
    fixture::validated(&fixture::entry_without_routing(&format!(
        r#""listeners": [{{ "port": {}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "limits": {{ "maxConnections": 2, "maxHandshakes": 2 }} }}"#,
        unused_loopback_port()
    )))
}

pub(super) fn unused_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .unwrap_or_else(|error: io::Error| panic!("reserve loopback port: {error}"))
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
