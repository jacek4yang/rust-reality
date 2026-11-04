//! The process-lifetime state a generation is published into.
//!
//! Everything here outlives every snapshot: the admission authorities, the
//! replay caches, the descriptor budget, the derived policy, and the atomic
//! cell holding the current generation. That is deliberate. A reload replaces
//! what a connection *reads*; it must never replace what bounds a connection,
//! or ten reloads would grant ten times the ceiling while old sessions still
//! hold old permits.

use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;

use crate::{
    config::{NodeConfig, load},
    logging::LogEvent,
    network::NetworkEnvironment,
    protocol::{handoff::HandoffReplayCache, reality::ReplayCache},
    runtime::{DirectBarrier, PressureGauge, ResourceGovernor, policy::EffectivePolicy},
    transport::{FdBudget, tcp_relay::TcpRelay},
};

use super::{
    error::RuntimeUpdateError, event::emit, reload::ensure_hot_compatible, resources::MemoryWatch,
    snapshot::RuntimeSnapshot,
};
use crate::server::{nxr::NxrReplayCache, warm_pool::WarmPoolAuthority};

/// Process-lifetime bounded replay caches for internal landing listeners,
/// retained across immutable runtime generations.
pub(super) struct ListenerReplays {
    pub(super) nxr: HashMap<SocketAddr, NxrReplayCache>,
    pub(super) handoff: HashMap<SocketAddr, HandoffReplayCache>,
}

pub(super) struct RuntimeStore {
    pub(super) current: ArcSwap<RuntimeSnapshot>,
    pub(super) policy: EffectivePolicy,
    pub(super) replay: ReplayCache,
    pub(super) listener_replays: ListenerReplays,
    pub(super) tcp_relay: TcpRelay,
    pub(super) fd_budget: FdBudget,
    pub(super) authorities: ProcessAuthorities,
    pub(super) pressure: PressureGauge,
    pub(super) memory: Option<MemoryWatch>,
    pub(super) generation: AtomicU64,
    pub(super) update: Mutex<()>,
}

/// Admission authorities built once at startup and shared by every generation.
///
/// Reload swaps routing and protocol snapshots only — these ceilings and
/// rate gates must never multiply while old sessions hold old permits.
pub(super) struct ProcessAuthorities {
    pub(super) governor: ResourceGovernor,
    pub(super) direct_barrier: DirectBarrier,
    pub(super) warm_pools: WarmPoolAuthority,
    pub(super) network_environment: NetworkEnvironment,
}

impl RuntimeStore {
    pub(super) fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    pub(super) fn reload_interval(&self) -> Duration {
        let node = self.load();
        let interval = node
            .node
            .as_entry()
            .and_then(|entry| entry.assets.as_ref())
            .map_or(
                crate::config::node::assets::DEFAULT_RELOAD_INTERVAL_SECONDS,
                crate::config::node::assets::AssetsConfig::reload_interval_seconds,
            );
        Duration::from_secs(interval)
    }

    pub(super) fn reload_path(&self, path: &Path) -> Result<u64, RuntimeUpdateError> {
        let config = load(path)?;
        self.publish(config.into_node())
    }

    pub(super) fn refresh(&self) -> Result<u64, RuntimeUpdateError> {
        let node = self.load().node.clone();
        self.publish(node)
    }

    pub(super) fn publish(&self, config: NodeConfig) -> Result<u64, RuntimeUpdateError> {
        let _guard = self
            .update
            .lock()
            .map_err(|_| RuntimeUpdateError::Unavailable)?;
        let current = self.load();
        let config = ensure_hot_compatible(&current, config)?;
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(RuntimeUpdateError::GenerationExhausted)?;
        let candidate = RuntimeSnapshot::compile(
            config,
            &self.policy,
            generation,
            self.replay.clone(),
            &self.listener_replays,
            self.tcp_relay.clone(),
            &self.pressure,
            &self.authorities,
        )?;
        self.current.store(Arc::new(candidate));
        self.generation.store(generation, Ordering::Release);
        // Publish first so an accept racing this update can only observe a
        // live old generation or the new one, never a retired handler. The old
        // snapshot remains locally owned here while its unused speculative
        // sockets are reclaimed immediately afterwards; checked-out sessions
        // retain their independent stream and permits.
        current.deactivate_warm_pools();
        let published = self.load();
        emit(
            &published.logger,
            &LogEvent::ConfigurationPublished {
                generation: published.generation,
            },
        );
        Ok(generation)
    }
}

#[cfg(test)]
mod tests;
