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
    // Nonces and their original expiry deadlines survive generation changes.
    // Rebuilding the cache would permit replay; silently keeping it would
    // ignore the new policy. Retention changes therefore require a restart.
    if replay_retention(&candidate) != replay_retention(&current.node) {
        return Err(RuntimeUpdateError::ReplayPolicyChanged);
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

fn replay_retention(node: &NodeConfig) -> Option<u64> {
    node.as_landing().map(|landing| match &landing.landing {
        LandingProtocol::Handoff(settings) => settings.nonce_retention_seconds(),
        LandingProtocol::Nxr(settings) => crate::server::nxr::replay_retention_seconds(
            settings.timing().max_time_difference_seconds,
        ),
    })
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
        NodeConfig::Client(_) => {
            // Client nodes never enter ProductionServer reload.
            ListenerRole::Entry
        }
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
mod tests;
