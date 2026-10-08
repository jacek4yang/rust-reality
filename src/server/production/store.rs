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
    error::RuntimeUpdateError,
    event::emit,
    reload::ensure_hot_compatible,
    resources::MemoryWatch,
    snapshot::{GenerationOrigin, Provenance, RuntimeSnapshot},
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
    /// Serializes whole update transactions (derive, validate, compile,
    /// commit). Held for a compile, exactly as a `SIGHUP` reload holds it.
    pub(super) update: Mutex<()>,
    /// The commit boundary: guards the instant a compiled candidate becomes
    /// current, and whether the store still accepts publications at all.
    /// Held only for that pointer swap and for pool activation, never for a
    /// compile, so shutdown waits microseconds rather than a whole compile.
    pub(super) commit: Mutex<CommitState>,
    /// Counts callers which have started acquiring the update mutex; test-only
    /// so concurrency regressions can synchronize without timing sleeps.
    #[cfg(test)]
    pub(super) update_waiters: std::sync::atomic::AtomicUsize,
}

/// Whether the store still accepts publications.
#[derive(Debug, Default)]
pub(super) struct CommitState {
    closed: bool,
}

/// The result of one update transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Published {
    /// The generation current when the transaction ended.
    pub(super) generation: u64,
    /// Whether the transaction published a new generation. A control change
    /// that leaves the configuration exactly as it was publishes nothing.
    pub(super) changed: bool,
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
        self.publish_as(GenerationOrigin::Configuration, config.into_node())
    }

    /// Recompiles the live configuration with freshly loaded assets.
    ///
    /// The configuration is taken from the generation that is current *under
    /// the update lock*, never from a copy read before it: a control change
    /// published while this refresh waited for the lock is the base it
    /// refreshes, not a change it silently reverts.
    pub(super) fn refresh(&self) -> Result<u64, RuntimeUpdateError> {
        self.publish_derived(GenerationOrigin::Assets, None, |current| {
            Ok::<_, RuntimeUpdateError>((current.node.clone(), ()))
        })
        .map(|(published, ())| published.generation)
    }

    /// Stops accepting publications and returns the final generation.
    ///
    /// Waits only for a commit already in progress (a pointer swap), never
    /// for a compile. A transaction still compiling when this returns fails
    /// with [`RuntimeUpdateError::ShuttingDown`] at its commit boundary, so
    /// the generation returned here is the last one that will ever be
    /// current and the caller may retire its pools without a racing
    /// publication activating new ones.
    pub(super) fn close(&self) -> Arc<RuntimeSnapshot> {
        let mut commit = self
            .commit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        commit.closed = true;
        self.load()
    }

    /// Starts speculative dialing for the current generation, unless the
    /// store has closed.
    ///
    /// Runs under the commit boundary so it cannot interleave with
    /// [`Self::close`]: either the pools start before shutdown retires them,
    /// or they never start.
    pub(super) fn activate_current(&self) {
        let commit = self
            .commit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !commit.closed {
            self.load().activate_warm_pools();
        }
    }

    #[cfg(test)]
    pub(super) fn publish(&self, config: NodeConfig) -> Result<u64, RuntimeUpdateError> {
        self.publish_as(GenerationOrigin::Configuration, config)
    }

    fn publish_as(
        &self,
        origin: GenerationOrigin,
        config: NodeConfig,
    ) -> Result<u64, RuntimeUpdateError> {
        self.publish_derived(origin, None, |_| Ok::<_, RuntimeUpdateError>((config, ())))
            .map(|(published, ())| published.generation)
    }

    /// Derives one candidate from the live generation and publishes it, as a
    /// single transaction under the update lock.
    ///
    /// `derive` sees the generation that is current *after* the lock is
    /// taken, so two concurrent updates can never both start from the same
    /// generation and silently discard each other's change. `expected` turns
    /// the transaction into compare-and-publish: when it no longer names the
    /// current generation, nothing is derived and nothing changes.
    ///
    /// A control change whose candidate equals the live configuration
    /// publishes nothing and reports the current generation. A control change
    /// that alters only `users` reuses the live generation's assets,
    /// outbounds, cover fallback, and warm pools (see
    /// [`RuntimeSnapshot::compile_identity`]); every other change compiles a
    /// complete generation.
    pub(super) fn publish_derived<T, E>(
        &self,
        origin: GenerationOrigin,
        expected: Option<u64>,
        derive: impl FnOnce(&RuntimeSnapshot) -> Result<(NodeConfig, T), E>,
    ) -> Result<(Published, T), E>
    where
        E: From<RuntimeUpdateError>,
    {
        #[cfg(test)]
        self.update_waiters.fetch_add(1, Ordering::AcqRel);
        let update = self.update.lock();
        #[cfg(test)]
        self.update_waiters.fetch_sub(1, Ordering::AcqRel);
        let _guard = update.map_err(|_| RuntimeUpdateError::Unavailable)?;
        let current = self.load();
        if let Some(expected) = expected
            && expected != current.generation
        {
            return Err(RuntimeUpdateError::GenerationConflict {
                expected,
                current: current.generation,
            }
            .into());
        }
        let (config, output) = derive(&current)?;
        if origin == GenerationOrigin::Control && config == current.node {
            return Ok((
                Published {
                    generation: current.generation,
                    changed: false,
                },
                output,
            ));
        }
        let config = ensure_hot_compatible(&current, config)?;
        let generation = self
            .generation
            .load(Ordering::Acquire)
            .checked_add(1)
            .ok_or(RuntimeUpdateError::GenerationExhausted)?;
        let provenance = Provenance {
            origin,
            // An asset refresh recompiles the live configuration as it is,
            // so it inherits whether that configuration still matches the
            // file; only a file reload makes the two agree again.
            control_changes: match origin {
                GenerationOrigin::Startup | GenerationOrigin::Configuration => false,
                GenerationOrigin::Assets => current.provenance.control_changes,
                GenerationOrigin::Control => true,
            },
        };
        let identity_only =
            origin == GenerationOrigin::Control && only_users_differ(&current.node, &config);
        let candidate = if identity_only {
            RuntimeSnapshot::compile_identity(&current, config, generation, provenance)?
        } else {
            RuntimeSnapshot::compile(
                config,
                &self.policy,
                generation,
                provenance,
                self.replay.clone(),
                &self.listener_replays,
                self.tcp_relay.clone(),
                &self.pressure,
                &self.authorities,
            )?
        };
        {
            let commit = self
                .commit
                .lock()
                .map_err(|_| RuntimeUpdateError::Unavailable)?;
            if commit.closed {
                return Err(RuntimeUpdateError::ShuttingDown.into());
            }
            self.current.store(Arc::new(candidate));
            self.generation.store(generation, Ordering::Release);
        }
        // Publish first so an accept racing this update can only observe a
        // live old generation or the new one, never a retired handler. The old
        // snapshot remains locally owned here while its unused speculative
        // sockets are reclaimed immediately afterwards; checked-out sessions
        // retain their independent stream and permits. An identity-only
        // generation shares the old one's pools, so only its pre-auth
        // generation retires.
        if identity_only {
            current.pre_auth_generation.deactivate();
        } else {
            current.deactivate_warm_pools();
        }
        let published = self.load();
        emit(
            &published.logger,
            &LogEvent::ConfigurationPublished {
                generation: published.generation,
            },
        );
        Ok((
            Published {
                generation,
                changed: true,
            },
            output,
        ))
    }
}

/// Whether `candidate` differs from `current` in the entry's `users` and in
/// nothing else.
///
/// Users decide who authenticates and which routing policy applies; nothing
/// that dials, listens, loads assets, or keeps a pool depends on them. Every
/// other difference — including any change to the REALITY section, the
/// routing rules, or the outbounds — takes the full compile.
fn only_users_differ(current: &NodeConfig, candidate: &NodeConfig) -> bool {
    match (current, candidate) {
        (NodeConfig::Entry(current), NodeConfig::Entry(candidate)) => {
            // Exhaustive on purpose: a field added to `EntryConfig` fails to
            // compile here until someone decides whether it is identity.
            let crate::config::EntryConfig {
                role,
                listeners,
                reality,
                users,
                outbounds,
                routing,
                assets,
                dns,
                network,
                log,
                runtime,
                control,
            } = &**current;
            *users != candidate.users
                && *role == candidate.role
                && *listeners == candidate.listeners
                && *reality == candidate.reality
                && *outbounds == candidate.outbounds
                && *routing == candidate.routing
                && *assets == candidate.assets
                && *dns == candidate.dns
                && *network == candidate.network
                && *log == candidate.log
                && *runtime == candidate.runtime
                && *control == candidate.control
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::Ordering};

    use super::{GenerationOrigin, Published, RuntimeStore};
    use crate::{
        runtime::AdmissionKind,
        server::production::{
            ProductionServer, RuntimeUpdateError,
            fixture::{
                cold_variant, entry_config, only_listener, outbounds_of, tiny_ceiling_config,
                unused_loopback_port, with_extra_outbound, with_extra_rule,
            },
            snapshot::{ConnectionHandler, RuntimeSnapshot},
        },
    };

    #[test]
    fn atomically_publishes_hot_runtime_generation() {
        let config = entry_config(8443);
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let previous = server.runtime.load();
        let replacement = with_extra_rule(8443, "hot").into_node();

        assert_eq!(
            server
                .runtime
                .publish(replacement)
                .expect("compatible snapshot must publish"),
            1
        );
        let current = server.runtime.load();
        assert_eq!(previous.generation, 0);
        assert_eq!(current.generation, 1);
        assert!(!Arc::ptr_eq(&previous, &current));
    }

    #[test]
    fn a_rejected_publication_must_not_advance_the_generation_counter() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let before = server.runtime.generation.load(Ordering::Acquire);

        let incompatible = cold_variant(config.node().listeners()[0].port);
        assert!(matches!(
            server.runtime.publish(incompatible),
            Err(RuntimeUpdateError::NetworkDialPolicyChanged)
        ));

        assert_eq!(
            server.runtime.generation.load(Ordering::Acquire),
            before,
            "a rejected candidate must leave the generation counter untouched, or the \
             next accepted publication silently skips a generation number"
        );
        assert_eq!(
            server.runtime.load().generation,
            before,
            "the live snapshot must still report the last good generation"
        );
    }

    #[test]
    fn generations_increment_by_exactly_one_and_never_repeat() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let mut seen = vec![server.runtime.load().generation];

        for round in 1..=4u64 {
            let accepted =
                with_extra_outbound(config.node().listeners()[0].port, &format!("probe-{round}"));
            let published = server
                .runtime
                .publish(accepted)
                .expect("an added outbound is a hot-compatible change");
            assert_eq!(
                published, round,
                "each accepted publication must advance the generation by exactly one"
            );

            let rejected = cold_variant(config.node().listeners()[0].port);
            assert!(server.runtime.publish(rejected).is_err());

            seen.push(published);
        }

        let mut unique = seen.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            seen.len(),
            "a generation number must never be reused: {seen:?}"
        );
        assert_eq!(seen, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn outbound_tables_are_replaced_wholesale_across_a_publication() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let before = only_listener(&server.runtime.load());
        assert!(outbounds_of(&before).contains("direct"));
        assert!(
            !outbounds_of(&before).contains("crossed"),
            "the first generation cannot know a tag introduced later"
        );

        server
            .runtime
            .publish(with_extra_outbound(
                config.node().listeners()[0].port,
                "crossed",
            ))
            .expect("an added outbound is hot-compatible");

        let after = only_listener(&server.runtime.load());
        assert!(
            outbounds_of(&after).contains("crossed"),
            "the published generation must expose its own outbound table"
        );
        assert!(
            outbounds_of(&after).contains("direct"),
            "the published table must be complete, not a partial overlay"
        );
        assert!(
            !Arc::ptr_eq(&before, &after),
            "a publication must install a freshly compiled listener runtime"
        );
    }

    #[test]
    fn an_in_flight_connection_keeps_its_own_generation_outbound_table() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");

        // A live connection holds exactly this: an Arc taken at accept time.
        let in_flight = only_listener(&server.runtime.load());

        server
            .runtime
            .publish(with_extra_outbound(
                config.node().listeners()[0].port,
                "next-generation",
            ))
            .expect("an added outbound is hot-compatible");

        assert!(
            !outbounds_of(&in_flight).contains("next-generation"),
            "a connection that started before the reload must never observe the new \
             generation's outbound table"
        );
        assert!(
            outbounds_of(&in_flight).contains("direct"),
            "the retired generation must stay usable until its sessions finish"
        );
        assert!(
            outbounds_of(&only_listener(&server.runtime.load())).contains("next-generation"),
            "newly accepted connections must observe the published generation"
        );
    }

    #[test]
    fn retiring_a_generation_deactivates_only_its_own_pre_auth_pool() {
        let config = entry_config(unused_loopback_port());
        let server = ProductionServer::from_config(config.clone()).expect("server must compile");
        let retired = server.runtime.load();

        server
            .runtime
            .publish(with_extra_outbound(
                config.node().listeners()[0].port,
                "pool-probe",
            ))
            .expect("an added outbound is hot-compatible");

        let published = server.runtime.load();
        assert!(
            !Arc::ptr_eq(&retired, &published),
            "the retired and published generations must be distinct objects"
        );
        assert!(
            !retired.pre_auth_generation.is_active(),
            "publish must retire the old generation's pre-auth pool"
        );
        assert!(
            published.pre_auth_generation.is_active(),
            "retiring the old generation must not deactivate the published one, or a \
             reload would strand every subsequent pre-auth connection"
        );
    }

    /// Runs a control-origin transaction on another thread whose derive step
    /// (which holds the update lock) parks until released, and reports when it
    /// is parked. Gives a test a deterministic "a mutation holds the lock" point.
    fn parked_control_publication(
        runtime: &Arc<RuntimeStore>,
        candidate: crate::config::NodeConfig,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<Result<Published, RuntimeUpdateError>>,
    ) {
        let (locked_sender, locked) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let runtime = Arc::clone(runtime);
        let thread = std::thread::spawn(move || {
            runtime
                .publish_derived(GenerationOrigin::Control, None, move |_| {
                    locked_sender.send(()).expect("the test is waiting");
                    released.recv().expect("the test releases the derive step");
                    Ok::<_, RuntimeUpdateError>((candidate, ()))
                })
                .map(|(published, ())| published)
        });
        (locked, release, thread)
    }

    #[test]
    fn an_asset_refresh_never_reverts_a_control_change_it_waited_behind() {
        let port = unused_loopback_port();
        let server = ProductionServer::from_config(entry_config(port)).expect("server");
        let runtime = &server.runtime;
        let changed = with_extra_outbound(port, "control-made");

        // G1 is being derived under the update lock.
        let (locked, release, control) = parked_control_publication(runtime, changed.clone());
        locked
            .recv()
            .expect("the control derive step holds the lock");

        // A refresh starts while G1 is in flight. Whatever it reads before
        // it reaches the lock, the base it publishes must be G1.
        let refresher = {
            let runtime = Arc::clone(runtime);
            std::thread::spawn(move || runtime.refresh())
        };
        // Wait until refresh has reached the update-lock acquisition while G1
        // still holds it. This makes the stale-base interleaving deterministic
        // without relying on scheduler timing.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while runtime.update_waiters.load(Ordering::Acquire) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the refresh must reach the update-lock wait"
            );
            std::thread::yield_now();
        }
        release.send(()).expect("release the control derive step");

        let control = control
            .join()
            .expect("control thread")
            .expect("G1 publishes");
        let refreshed = refresher
            .join()
            .expect("refresh thread")
            .expect("G2 publishes");
        assert_eq!((control.generation, refreshed), (1, 2));

        let live = runtime.load();
        assert_eq!(live.generation, 2);
        assert_eq!(
            live.node, changed,
            "the refresh must recompile the control change, not the generation it replaced"
        );
        assert_eq!(live.provenance.origin, GenerationOrigin::Assets);
        assert!(live.provenance.control_changes);
        assert!(outbounds_of(&only_listener(&live)).contains("control-made"));
    }

    #[test]
    fn closing_the_store_refuses_a_publication_still_compiling() {
        let port = unused_loopback_port();
        let server = ProductionServer::from_config(entry_config(port)).expect("server");
        let runtime = &server.runtime;

        let (locked, release, control) =
            parked_control_publication(runtime, with_extra_outbound(port, "late"));
        locked
            .recv()
            .expect("the derive step holds the update lock");

        // Shutdown begins mid-transaction. Closing must not wait for the
        // compile (the commit lock is free), and the generation it returns is
        // the last one that will ever be current.
        let last = runtime.close();
        assert_eq!(last.generation, 0);
        release.send(()).expect("release");

        assert!(matches!(
            control.join().expect("control thread"),
            Err(RuntimeUpdateError::ShuttingDown)
        ));
        assert!(Arc::ptr_eq(&last, &runtime.load()));
        assert_eq!(runtime.generation.load(Ordering::Acquire), 0);
        assert!(
            last.pre_auth_generation.is_active(),
            "a refused commit must not retire the live generation"
        );
        assert!(matches!(
            runtime.refresh(),
            Err(RuntimeUpdateError::ShuttingDown)
        ));
    }

    #[test]
    fn a_control_change_that_changes_nothing_publishes_nothing() {
        let server =
            ProductionServer::from_config(entry_config(unused_loopback_port())).expect("server");
        let before = server.runtime.load();
        let (published, ()) = server
            .runtime
            .publish_derived(GenerationOrigin::Control, Some(0), |current| {
                Ok::<_, RuntimeUpdateError>((current.node.clone(), ()))
            })
            .expect("a no-op is not an error");
        assert_eq!(
            published,
            Published {
                generation: 0,
                changed: false
            }
        );
        assert!(Arc::ptr_eq(&before, &server.runtime.load()));
        assert!(before.pre_auth_generation.is_active());
    }

    #[test]
    fn a_users_only_change_reuses_assets_and_pools_and_recompiles_identity() {
        let port = unused_loopback_port();
        let server = ProductionServer::from_config(entry_config(port)).expect("server");
        let runtime = &server.runtime;
        let previous = runtime.load();
        let mut candidate = previous.node.clone();
        if let crate::config::NodeConfig::Entry(entry) = &mut candidate {
            entry.users[0].enabled = Some(false);
            let mut extra = entry.users[0].clone();
            extra.id = crate::config::node::fixture::uuid(0x22);
            extra.short_ids = vec!["5a5a".to_owned()];
            extra.enabled = None;
            entry.users.push(extra);
        }
        let (published, ()) = runtime
            .publish_derived(GenerationOrigin::Control, None, |_| {
                Ok::<_, RuntimeUpdateError>((candidate.clone(), ()))
            })
            .expect("a users-only change publishes");
        assert!(published.changed);
        let live = runtime.load();
        assert_eq!(live.node, candidate);

        let same_assets = |a: &RuntimeSnapshot, b: &RuntimeSnapshot| match (&a.assets, &b.assets) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        assert!(
            same_assets(&previous, &live),
            "no asset is loaded again for an identity change"
        );
        let cover_generation = |snapshot: &RuntimeSnapshot| match &only_listener(snapshot).handler {
            ConnectionHandler::Public { reality, .. } => {
                reality.cover_pool_snapshot().map(|pool| pool.generation)
            }
            _ => None,
        };
        assert_eq!(
            cover_generation(&previous),
            Some(0),
            "the fixture keeps a warm cover pool"
        );
        assert_eq!(
            cover_generation(&live),
            Some(0),
            "the cover pool is taken over, not rebuilt cold"
        );
        assert!(!previous.pre_auth_generation.is_active());
        assert!(live.pre_auth_generation.is_active());

        // Any change beyond users takes the full compile.
        let (full, ()) = runtime
            .publish_derived(GenerationOrigin::Control, None, |_| {
                Ok::<_, RuntimeUpdateError>((with_extra_outbound(port, "beyond-users"), ()))
            })
            .expect("a hot change publishes");
        assert!(full.changed);
        let rebuilt = runtime.load();
        assert!(!same_assets(&live, &rebuilt));
        assert_eq!(cover_generation(&rebuilt), Some(full.generation));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_cannot_multiply_the_connection_ceiling() {
        let server = ProductionServer::from_config(tiny_ceiling_config()).expect("must compile");
        let governor = server.runtime.authorities.governor.clone();
        let permit_a = governor
            .try_acquire(AdmissionKind::Connection)
            .expect("first connection must be admitted");
        let permit_b = governor
            .try_acquire(AdmissionKind::Connection)
            .expect("second connection must be admitted");
        assert!(
            governor.try_acquire(AdmissionKind::Connection).is_err(),
            "the ceiling must hold before any reload"
        );

        for generation in 1..=10 {
            server
                .runtime
                .refresh()
                .unwrap_or_else(|error| panic!("reload {generation} must succeed: {error}"));
        }

        assert!(
            server
                .runtime
                .authorities
                .governor
                .try_acquire(AdmissionKind::Connection)
                .is_err(),
            "ten reloads must not multiply the connection ceiling"
        );
        drop(permit_a);
        assert!(
            server
                .runtime
                .authorities
                .governor
                .try_acquire(AdmissionKind::Connection)
                .is_ok(),
            "releasing an old-generation permit must free capacity after reloads"
        );
        drop(permit_b);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reload_cannot_reset_the_direct_dial_rate_gate() {
        let server = ProductionServer::from_config(tiny_ceiling_config()).expect("must compile");
        // The barrier is derived, so its width is whatever the machine
        // supports; exhaust exactly that many permits rather than assuming one.
        let width = server.runtime.policy.direct_barrier.max_concurrent;
        let mut held: Vec<_> = (0..width.saturating_sub(1))
            .map(|_| {
                server
                    .runtime
                    .authorities
                    .direct_barrier
                    .try_acquire()
                    .expect("every derived direct permit must be acquirable")
            })
            .collect();
        let permit = server
            .runtime
            .authorities
            .direct_barrier
            .try_acquire()
            .expect("the last direct concurrency permit must be acquirable");
        assert!(
            server
                .runtime
                .authorities
                .direct_barrier
                .try_acquire()
                .is_err()
        );

        for _ in 0..10 {
            server.runtime.refresh().expect("reload must succeed");
        }

        assert!(
            server
                .runtime
                .authorities
                .direct_barrier
                .try_acquire()
                .is_err(),
            "ten reloads must not reset direct concurrency"
        );
        drop(permit);
        assert!(
            server
                .runtime
                .authorities
                .direct_barrier
                .try_acquire()
                .is_ok(),
            "releasing the permit must free the rate gate after reloads"
        );
        held.clear();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_dropped_spawn_blocking_waiter_cannot_publish_after_shutdown() {
        let port = unused_loopback_port();
        let server = ProductionServer::from_config(entry_config(port)).expect("server");
        let runtime = Arc::clone(&server.runtime);
        let candidate = with_extra_outbound(port, "late-control-update");
        let (entered_sender, entered) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (finished_sender, finished) = std::sync::mpsc::channel();

        let waiter = tokio::task::spawn_blocking(move || {
            let result = runtime.publish_derived(GenerationOrigin::Control, None, move |_| {
                entered_sender.send(()).expect("test is waiting");
                released.recv().expect("test releases the update");
                Ok::<_, RuntimeUpdateError>((candidate, ()))
            });
            finished_sender
                .send(result.map(|(published, ())| published))
                .expect("test observes the blocking task result");
        });

        entered
            .recv()
            .expect("the blocking update is in flight under the update lock");
        // This is what dropping a cancelled connection's JoinHandle does: it
        // drops the async waiter, not the already-started blocking closure.
        drop(waiter);
        let last = server.runtime.close();
        assert_eq!(last.generation, 0);
        release.send(()).expect("release the blocking update");

        assert!(matches!(
            finished
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("blocking closure must finish"),
            Err(RuntimeUpdateError::ShuttingDown)
        ));
        assert!(Arc::ptr_eq(&last, &server.runtime.load()));
        assert_eq!(server.runtime.generation.load(Ordering::Acquire), 0);
        assert!(last.pre_auth_generation.is_active());
    }
}
