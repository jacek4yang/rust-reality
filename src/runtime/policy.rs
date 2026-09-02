//! The effective numeric policy the runtime executes.
//!
//! These numbers used to live in the configuration model, where every one of
//! them was an operator-facing field. Most of them are not decisions an
//! operator has information to make: buffer sizes, pool capacities, admission
//! sub-limits, replay retention, and warm-connection sizing all follow from CPU
//! count, memory boundary, and descriptor budget, which the process measures
//! and the operator would have to guess.
//!
//! So they moved here. The configuration now carries a small set of expert
//! overrides (`runtime.limits`), and everything else is derived at startup.
//! What arrives in this module is the *result* — a policy with no absent
//! values, no defaults left to apply, and no serde derive, because nothing
//! reads or writes it as configuration.
//!
//! Keeping these as plain data rather than folding them into one flat struct
//! is deliberate: each group is handed to the subsystem that owns it, so the
//! relay never sees admission limits and the governor never sees buffer sizes.

/// The complete effective policy for one process generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EffectivePolicy {
    /// Global admission limits.
    pub governor: ResourceGovernorPolicy,
    /// Direct-outbound isolation.
    pub direct_barrier: DirectBarrierPolicy,
    /// Relay buffering and Linux acceleration.
    pub relay: RelayPolicy,
    /// Per-endpoint warm TCP behaviour.
    pub warm_connections: WarmConnectionPolicy,
}

/// Connection and pre-authentication admission limits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceGovernorPolicy {
    /// Total accepted connections.
    pub max_connections: u32,
    /// Concurrent pre-authentication handshakes.
    pub max_handshakes: u32,
    /// Accepted internal sockets that have sent no protocol bytes. These
    /// speculative idle sockets are reclaimed before active authentication.
    pub max_pre_auth_idle_connections: u32,
    /// Concurrent cover fallbacks.
    pub max_fallbacks: u32,
    /// Concurrent expensive cryptographic operations.
    pub max_crypto_operations: u32,
    /// Replay entries across pending and committed states.
    pub max_replay_entries: u32,
    /// Concurrent DNS resolutions, bounded until the underlying lookup
    /// finishes rather than until the async wait ends.
    pub max_dns_lookups: u32,
    /// Retention after a verified TLS ClientFinished.
    pub replay_retention_ms: u64,
    /// Absolute ClientHello read deadline.
    pub client_hello_timeout_ms: u64,
    /// Absolute authenticated handshake deadline.
    pub handshake_timeout_ms: u64,
    /// Cover and outbound connection deadline.
    pub connect_timeout_ms: u64,
    /// Largest fallback lifetime.
    pub fallback_timeout_ms: u64,
}

impl Default for ResourceGovernorPolicy {
    fn default() -> Self {
        Self {
            max_connections: 16_384,
            max_handshakes: 1_024,
            max_pre_auth_idle_connections: 1_024,
            max_fallbacks: 512,
            max_crypto_operations: 128,
            max_replay_entries: 65_536,
            max_dns_lookups: 64,
            replay_retention_ms: 120_000,
            client_hello_timeout_ms: 3_000,
            handshake_timeout_ms: 10_000,
            connect_timeout_ms: 10_000,
            fallback_timeout_ms: 120_000,
        }
    }
}

/// Direct-outbound admission isolation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectBarrierPolicy {
    /// Concurrent direct dials.
    pub max_concurrent: u32,
    /// New direct dials allowed per second.
    pub max_per_second: u32,
}

impl Default for DirectBarrierPolicy {
    fn default() -> Self {
        Self {
            max_concurrent: 2_048,
            max_per_second: 4_096,
        }
    }
}

/// Relay buffering and Linux acceleration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPolicy {
    /// Bytes per pooled userspace buffer.
    pub buffer_bytes: usize,
    /// Largest number of pooled buffers.
    pub max_pooled_buffers: usize,
    /// Largest number of concurrent Linux splice relays and their pipe pairs.
    pub max_splice_relays: u32,
    /// Ceiling on relay buffer memory across every backend.
    pub max_relay_memory_bytes: u64,
    /// Permit non-blocking splice on plaintext TCP boundaries.
    pub splice: bool,
    /// Reuse splice pipes process-wide instead of creating and destroying them
    /// per relay: size once at creation, no pipe syscalls on a pool hit.
    pub pipe_pool: bool,
    /// Largest number of retained pipe pairs in the process pool.
    pub max_pooled_pipes: u32,
}

impl Default for RelayPolicy {
    fn default() -> Self {
        Self {
            buffer_bytes: 32 * 1024,
            max_pooled_buffers: 4_096,
            max_splice_relays: 256,
            max_relay_memory_bytes: 536_870_912,
            splice: true,
            pipe_pool: true,
            // Keeps the accounted pool term at 256 MiB with the 512 KiB splice
            // pipe capacity (256 pairs x 2 pipes x 512 KiB).
            max_pooled_pipes: 256,
        }
    }
}

/// Bounded adaptive warm TCP policy, shared by eligible internal transports.
///
/// The ready, connecting, and refill bounds are per endpoint. The runtime
/// derives a strict process-wide bound from these values and the number of
/// configured endpoints, and the descriptor budget remains the final limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WarmConnectionPolicy {
    /// Ready sockets maintained during low demand.
    pub min_ready: u32,
    /// Largest number of ready sockets retained by one endpoint pool.
    pub max_ready: u32,
    /// Largest number of simultaneous speculative dials by one endpoint pool.
    pub max_connecting: u32,
    /// Largest number of dials submitted by one reconciliation pass.
    pub refill_batch: u32,
    /// Largest idle age before an unused socket is discarded.
    pub idle_timeout_ms: u64,
    /// Largest absolute age of an unused socket.
    pub max_lifetime_ms: u64,
    /// Demand-free interval before gradual shrink begins.
    pub shrink_delay_ms: u64,
}

impl Default for WarmConnectionPolicy {
    fn default() -> Self {
        Self {
            min_ready: 4,
            max_ready: 256,
            max_connecting: 64,
            refill_batch: 16,
            idle_timeout_ms: 30_000,
            max_lifetime_ms: 300_000,
            shrink_delay_ms: 30_000,
        }
    }
}

/// Supported process resource modes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ResourceMode {
    /// Shared-machine posture; every budget derives from inherited limits.
    #[default]
    Standard,
    /// Single-tenant posture; the process budgets against the whole machine or
    /// cgroup and supervises its own memory pressure.
    Dedicated,
}

impl ResourceMode {
    /// The stable identifier used in logs and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Dedicated => "dedicated",
        }
    }
}

/// Resolves the declared machine tenancy against what the machine shows.
///
/// `auto` resolves to [`ResourceMode::Dedicated`] only when the cgroup v2
/// tenancy boundary is fully observable — a finite CPU quota and a finite
/// memory ceiling. It never assumes a dedicated machine on bare metal, where
/// the boundary cannot be observed and guessing wrong would budget against
/// memory the process does not own.
#[must_use]
pub fn resolve_resource_mode(
    profile: crate::config::node::runtime::RuntimeProfile,
    machine: &crate::runtime::machine::MachineReport,
) -> ResourceMode {
    use crate::config::node::runtime::RuntimeProfile;
    match profile {
        RuntimeProfile::Shared => ResourceMode::Standard,
        RuntimeProfile::Dedicated => ResourceMode::Dedicated,
        RuntimeProfile::Auto => {
            if machine.tenancy_boundary_observable() {
                ResourceMode::Dedicated
            } else {
                ResourceMode::Standard
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EffectivePolicy, ResourceMode};

    #[test]
    fn the_default_policy_is_internally_consistent() {
        let policy = EffectivePolicy::default();

        assert!(policy.governor.max_handshakes <= policy.governor.max_connections);
        assert!(policy.governor.max_fallbacks <= policy.governor.max_connections);
        assert!(policy.governor.max_crypto_operations <= policy.governor.max_handshakes);
        assert!(policy.governor.max_dns_lookups <= policy.governor.max_connections);
        assert!(policy.governor.client_hello_timeout_ms <= policy.governor.handshake_timeout_ms);
        assert!(policy.governor.connect_timeout_ms <= policy.governor.fallback_timeout_ms);
        assert!(policy.direct_barrier.max_concurrent <= policy.governor.max_connections);
        assert!(policy.warm_connections.min_ready <= policy.warm_connections.max_ready);
        assert!(policy.warm_connections.max_connecting <= policy.warm_connections.max_ready);
        assert!(policy.warm_connections.refill_batch <= policy.warm_connections.max_connecting);
        assert!(policy.warm_connections.idle_timeout_ms <= policy.warm_connections.max_lifetime_ms);
    }

    #[test]
    fn resource_mode_names_are_stable() {
        assert_eq!(ResourceMode::Standard.as_str(), "standard");
        assert_eq!(ResourceMode::Dedicated.as_str(), "dedicated");
        assert_eq!(ResourceMode::default(), ResourceMode::Standard);
    }
}
