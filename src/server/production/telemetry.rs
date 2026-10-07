//! Read-only current-generation observations for embedded service managers.

use std::sync::{Arc, Weak};

use serde::Serialize;

use super::{snapshot::ConnectionHandler, store::RuntimeStore};
use crate::server::{outbound::WarmOutboundKind, warm_pool::WarmPoolSnapshot};

/// A cloneable observer that never owns the server's runtime lifetime.
///
/// This is an in-process library interface, not a network management endpoint.
#[derive(Clone)]
pub struct TransportTelemetry {
    runtime: Weak<RuntimeStore>,
}

impl TransportTelemetry {
    pub(super) fn new(runtime: &Arc<RuntimeStore>) -> Self {
        Self {
            runtime: Arc::downgrade(runtime),
        }
    }

    /// Collects fixed-cardinality, secret-free current-generation pool totals.
    ///
    /// Returns `None` after the runtime has been dropped. Before `run`, pools
    /// can exist without being active; availability is not readiness or health.
    /// Each call temporarily pins the runtime and one immutable configuration
    /// generation until it returns, but
    /// counters across pools are sampled separately, not transactionally.
    /// Retired-generation sessions are excluded. Consumers must key deltas by
    /// generation: reload replaces pools and their cumulative counters.
    ///
    /// Collection creates no network activity, task, or intermediate vector.
    /// It briefly takes each pool's existing state lock; callers control their
    /// sampling rate and should not poll on the per-packet path.
    #[must_use]
    pub fn snapshot(&self) -> Option<TransportTelemetrySnapshot> {
        let runtime = self.runtime.upgrade()?;
        let current = runtime.load();
        let mut result = TransportTelemetrySnapshot {
            generation: current.generation,
            ..TransportTelemetrySnapshot::default()
        };
        // RuntimeSnapshot::compile creates one handler shared by every bound
        // address. Count its cover pool once, including dual-stack listeners.
        if let Some(connection) = current.connections.values().next()
            && let ConnectionHandler::Public { reality, .. } = &connection.handler
            && let Some(pool) = reality.cover_pool_snapshot()
        {
            result.cover.add(pool);
        }
        current.outbounds.visit_warm_pool_snapshots(|snapshot| {
            let totals = match snapshot.transport {
                WarmOutboundKind::Handoff => &mut result.handoff,
                WarmOutboundKind::Nxr => &mut result.nxr,
                WarmOutboundKind::Socks5 => &mut result.socks5,
            };
            totals.add(snapshot.pool);
        });
        Some(result)
    }
}

/// Fixed transport classes for a single observed configuration generation.
///
/// Contains no targets, listener addresses, outbound names, user identifiers,
/// credentials, error messages, or traffic content. Values are observations,
/// not a readiness/health verdict or process-wide session accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportTelemetrySnapshot {
    /// Configuration generation owning every pool represented here.
    pub generation: u64,
    /// The shared REALITY cover pool, counted once across listeners.
    pub cover: TransportPoolTotals,
    /// Aggregate Handoff outbound pools.
    pub handoff: TransportPoolTotals,
    /// Aggregate NXR outbound pools.
    pub nxr: TransportPoolTotals,
    /// Aggregate SOCKS5 outbound pools.
    pub socks5: TransportPoolTotals,
}

/// Saturating integer aggregates; absent transport classes contain zeros.
///
/// Gauges and cumulative counters can change during observation. In particular,
/// `hits + misses` need not equal `checkouts` in a concurrent snapshot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportPoolTotals {
    /// Number of represented pools, including inactive pools before startup.
    pub pools: u64,
    /// Sockets currently waiting in ready pools.
    pub ready: u64,
    /// Speculative TCP connection attempts in progress.
    pub connecting: u64,
    /// Checked-out sockets retained by current-generation operations.
    pub checked_out: u64,
    /// Cumulative checkout attempts.
    pub checkouts: u64,
    /// Cumulative successful ready-socket checkouts.
    pub hits: u64,
    /// Cumulative checkout misses.
    pub misses: u64,
    /// Cumulative misses falling back to an ordinary cold connection.
    pub cold_fallbacks: u64,
    /// Cumulative failed speculative dials; cancellation is not a failure.
    pub dial_failures: u64,
    /// Cumulative deadline failures.
    pub timeouts: u64,
    /// Cumulative explicit resource denials or allocation failures.
    pub resource_failures: u64,
    /// Cumulative address-policy rejections.
    pub policy_failures: u64,
    /// Cumulative other I/O failures, without retaining error text.
    pub io_failures: u64,
    /// Cumulative closed or expired ready-socket discards.
    pub stale_discards: u64,
    /// Maximum remaining speculative backoff, rounded down to milliseconds.
    pub max_backoff_ms: u64,
}

impl TransportPoolTotals {
    fn add(&mut self, pool: WarmPoolSnapshot) {
        self.pools = self.pools.saturating_add(1);
        self.ready = self.ready.saturating_add(u64::from(pool.ready));
        self.connecting = self.connecting.saturating_add(u64::from(pool.connecting));
        self.checked_out = self.checked_out.saturating_add(pool.in_use);
        self.checkouts = self.checkouts.saturating_add(pool.checkout_total);
        self.hits = self.hits.saturating_add(pool.checkout_hit);
        self.misses = self.misses.saturating_add(pool.checkout_miss);
        self.cold_fallbacks = self.cold_fallbacks.saturating_add(pool.cold_fallback);
        self.dial_failures = self.dial_failures.saturating_add(pool.connect_failure);
        self.timeouts = self.timeouts.saturating_add(pool.connect_timeout);
        self.resource_failures = self.resource_failures.saturating_add(pool.connect_resource);
        self.policy_failures = self.policy_failures.saturating_add(pool.connect_policy);
        self.io_failures = self.io_failures.saturating_add(pool.connect_io);
        self.stale_discards = self.stale_discards.saturating_add(pool.stale_discard);
        self.max_backoff_ms = self.max_backoff_ms.max(pool.backoff_remaining_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::production::{ProductionServer, fixture};

    #[test]
    fn observer_follows_generation_without_extending_server_lifetime() {
        let server = ProductionServer::from_config(fixture::entry_config(8443))
            .expect("fixture must compile");
        let owners = Arc::strong_count(&server.runtime);
        let observer = server.telemetry();
        let second = observer.clone();
        assert_eq!(Arc::strong_count(&server.runtime), owners);
        let initial = observer.snapshot().expect("runtime exists");
        assert_eq!(initial.generation, 0);
        assert_eq!(initial.cover.pools, 1);
        assert_eq!(
            initial.handoff.pools + initial.nxr.pools + initial.socks5.pools,
            0
        );
        server
            .runtime
            .publish(fixture::with_extra_rule(8443, "private-rule-name").into_node())
            .expect("hot reload must publish");
        assert_eq!(observer.snapshot().expect("new generation").generation, 1);
        assert_eq!(initial.generation, 0, "returned values do not mutate");
        let serving = server.run_until(async { Ok(()) });
        assert!(
            observer.snapshot().is_some(),
            "moving into run preserves observation"
        );
        drop(serving);
        assert!(observer.snapshot().is_none());
        assert!(second.snapshot().is_none());
    }

    #[test]
    fn shared_cover_is_counted_once_and_serialization_has_no_identities() {
        let config = crate::config::node::fixture::validated(
            &crate::config::node::fixture::entry_without_routing(
                r#""listeners": [
                    {"port":8443,"ip":"ipv4Only","ipv4":"127.0.0.1"},
                    {"port":8444,"ip":"ipv4Only","ipv4":"127.0.0.1"}],
                    "routing":{"default":"direct"}"#,
            ),
        );
        let server = ProductionServer::from_config(config).expect("fixture must compile");
        assert_eq!(server.runtime.load().connections.len(), 2);
        let snapshot = server.telemetry().snapshot().expect("runtime exists");
        assert_eq!(snapshot.cover.pools, 1);
        let json = serde_json::to_value(snapshot).expect("integer snapshot serializes");
        let object = json.as_object().expect("object");
        assert_eq!(object.len(), 5);
        for field in ["generation", "cover", "handoff", "nxr", "socks5"] {
            assert!(object.contains_key(field));
        }
        let encoded = json.to_string();
        for private in [
            "127.0.0.1",
            "8443",
            "8444",
            "privateKey",
            "shortIds",
            "users",
            "target",
        ] {
            assert!(!encoded.contains(private));
        }
    }

    #[test]
    fn aggregation_saturates_without_allocating_or_retaining_input() {
        let server = ProductionServer::from_config(fixture::entry_config(8443))
            .expect("fixture must compile");
        let current = server.runtime.load();
        let connection = current.connections.values().next().expect("one handler");
        let ConnectionHandler::Public { reality, .. } = &connection.handler else {
            panic!("entry fixture must be public");
        };
        let mut pool = reality.cover_pool_snapshot().expect("cover pool exists");
        pool.checkout_total = u64::MAX;
        pool.backoff_remaining_ms = 100;
        let mut total = TransportPoolTotals::default();
        let allocation = allocation_counter::measure(|| {
            total.add(pool);
            total.add(pool);
        });
        assert_eq!(allocation.count_total, 0);
        assert_eq!(total.pools, 2);
        assert_eq!(total.checkouts, u64::MAX);
        assert_eq!(total.max_backoff_ms, 100);
        // The complete observer path also needs no intermediate allocation.
        let observer = server.telemetry();
        let allocation = allocation_counter::measure(|| {
            std::hint::black_box(observer.snapshot());
        });
        assert_eq!(allocation.count_total, 0);
    }
    #[test]
    fn hashed_outbound_projection_is_fixed_size_and_allocation_free() {
        let config = crate::config::node::fixture::validated(
            &crate::config::node::fixture::entry_without_routing(
                r#""listeners":[{"port":8443,"ip":"ipv4Only","ipv4":"127.0.0.1"}],
                "outbounds":{
                    "private-a":{"type":"socks5","address":"127.0.0.1","port":9001,"warmTcp":true},
                    "private-b":{"type":"socks5","address":"127.0.0.1","port":9002,"warmTcp":true},
                    "private-c":{"type":"socks5","address":"127.0.0.1","port":9003,"warmTcp":true}},
                "routing":{"default":"direct"}"#,
            ),
        );
        let server = ProductionServer::from_config(config).expect("fixture must compile");
        let observer = server.telemetry();
        let first = observer.snapshot().expect("runtime exists");
        assert_eq!(first.socks5.pools, 3);
        assert_eq!(first.cover.pools, 1);
        assert_eq!(first.socks5.ready + first.socks5.connecting, 0);
        let allocations = allocation_counter::measure(|| {
            assert_eq!(observer.snapshot(), Some(first));
        });
        assert_eq!(allocations.count_total, 0);
        let json = serde_json::to_string(&first).expect("snapshot serializes");
        assert!(!json.contains("private-"));
        assert!(!json.contains("127.0.0.1"));
    }
}
