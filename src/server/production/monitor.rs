//! Periodic resource maintenance, adaptation, and network refresh.
//!
//! None of them sits in a data path. The resource monitor samples once a
//! second, the adaptive controller ticks once every five, and the route
//! refresh runs on the dial policy's own interval — so a sustained condition
//! costs a couple of log lines rather than one per event. All three share the
//! same cancellable sleep-or-shutdown shape, which is what keeps shutdown
//! prompt without any of them holding a lock across an await.

use std::{sync::Arc, time::Duration};

use tokio::{sync::watch, time};

use crate::{
    config::{NodeConfig, node::runtime::TuningMode},
    logging::LogEvent,
    network::NetworkEnvironment,
    runtime::{PressureGauge, ResourcePressure, adaptive, policy::EffectivePolicy},
};

use super::{
    event::emit,
    resources::MemoryWatch,
    store::{ProcessAuthorities, RuntimeStore},
};

/// How often the memory pressure monitor samples its bounded signal.
///
/// One sample per second is cheap (one small file read), fast enough to
/// refuse new work well before a cgroup OOM kill, and slow enough that it
/// can never show up in a profile of the data path.
const MEMORY_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

/// Reclaims expired replay occupancy in every resource mode. When a memory
/// watch exists, also samples pressure and publishes transitions. Debug ownership
/// observations share this fixed cadence, outside all data paths.
pub(super) async fn run_resource_monitor(
    runtime: Arc<RuntimeStore>,
    watch: Option<MemoryWatch>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut memory_state = ResourcePressure::Normal;
    let mut last_usage: Option<u64> = None;
    let mut last_source = watch
        .as_ref()
        .map(|watch| watch.sampler.configured_source());
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = time::sleep(MEMORY_SAMPLE_INTERVAL) => {}
        }
        if *shutdown.borrow() {
            break;
        }
        // Logical expiry was already enforced on admission. Reclaim idle
        // occupancy on the maintenance cadence as well, without shortening any
        // authentication/replay deadline or rebuilding a cache on reload.
        runtime.replay.purge_expired();
        for replay in runtime.listener_replays.handoff.values() {
            replay.purge_expired();
        }
        for replay in runtime.listener_replays.nxr.values() {
            replay.purge_expired();
        }
        emit_ownership(&runtime);
        let Some(watch) = watch.as_ref() else {
            continue;
        };
        let fd_state = ResourcePressure::from(runtime.fd_budget.pressure());
        if let Some(reading) = watch.sampler.sample() {
            // An unreadable sample keeps the previous state: a monitoring gap
            // must never itself raise or clear an alarm. A sampler that falls
            // back to a different source reports the source actually used,
            // so a fallback can never masquerade as the configured source.
            if Some(reading.source) != last_source {
                let snapshot = runtime.load();
                emit(
                    &snapshot.logger,
                    &LogEvent::MemorySamplerChanged {
                        from: last_source.unwrap_or(reading.source).as_str(),
                        to: reading.source.as_str(),
                    },
                );
                last_source = Some(reading.source);
            }
            last_usage = Some(reading.bytes);
            memory_state = watch.plan.classify(memory_state, reading.bytes);
        }
        let effective = fd_state.max(memory_state);
        if runtime.pressure.set(effective) {
            let snapshot = runtime.load();
            emit(
                &snapshot.logger,
                &LogEvent::ResourcePressureChanged {
                    pressure_state: effective.as_str(),
                    fd_pressure_state: runtime.fd_budget.pressure().as_str(),
                    memory_bytes_in_use: last_usage,
                    memory_pressure_enter: watch.plan.pressure_enter(),
                    memory_critical_enter: watch.plan.critical_enter(),
                },
            );
        }
    }
}

// Debug-only observations on the existing maintenance cadence, never on a
// connection, record, or relay path. No endpoint, credential or packet data.
fn emit_ownership(runtime: &RuntimeStore) {
    let snapshot = runtime.load();
    if !snapshot.logger.debug_enabled() {
        return;
    }
    let (warm_ready, warm_connecting) = runtime.authorities.warm_pools.counts();
    #[cfg(target_os = "linux")]
    let pipes = runtime.tcp_relay.pipe_pool_stats();
    #[cfg(target_os = "linux")]
    let (retained_pipe_pairs, retained_pipe_bytes, pipe_pair_capacity) =
        pipes.map_or((Some(0), Some(0), Some(0)), |pipes| {
            (
                Some(pipes.retained_pairs),
                pipes.pending_bytes,
                Some(pipes.retained_capacity),
            )
        });
    #[cfg(not(target_os = "linux"))]
    let (retained_pipe_pairs, retained_pipe_bytes, pipe_pair_capacity) = (None, None, None);
    let governor = &runtime.policy.governor;
    let admission = &runtime.authorities.governor;
    let mut replay_capacity = u64::from(governor.max_replay_entries);
    let mut replay_expiry_ms = governor
        .replay_retention_ms
        .max(governor.handshake_timeout_ms);
    for (capacity, retention) in runtime
        .listener_replays
        .handoff
        .values()
        .map(|cache| cache.retention_policy())
        .chain(
            runtime
                .listener_replays
                .nxr
                .values()
                .map(|cache| cache.retention_policy()),
        )
    {
        replay_capacity = replay_capacity.saturating_add(capacity as u64);
        replay_expiry_ms =
            replay_expiry_ms.max(u64::try_from(retention.as_millis()).unwrap_or(u64::MAX));
    }
    emit(
        &snapshot.logger,
        &LogEvent::ResourceOwnership {
            handshakes: admission.in_flight(crate::runtime::AdmissionKind::Handshake),
            fallbacks: admission.in_flight(crate::runtime::AdmissionKind::Fallback),
            crypto_operations: admission.in_flight(crate::runtime::AdmissionKind::CryptoOperation),
            dns_lookups: admission.in_flight(crate::runtime::AdmissionKind::DnsLookup),
            pre_auth_idle_connections: admission
                .in_flight(crate::runtime::AdmissionKind::PreAuthIdle),
            pre_auth_idle_capacity: u64::from(governor.max_pre_auth_idle_connections),
            fd_capacity: runtime.fd_budget.capacity(),
            pipe_pair_capacity,
            warm_socket_capacity: runtime.authorities.warm_pools.capacity(),
            replay_capacity,
            replay_expiry_ms,
            retirement_deadline_ms: governor
                .fallback_timeout_ms
                .max(governor.handshake_timeout_ms)
                .max(governor.connect_timeout_ms)
                .max(governor.client_hello_timeout_ms)
                .max(
                    u64::try_from(crate::io_activity::WRITE_STALL_TIMEOUT.as_millis())
                        .unwrap_or(u64::MAX),
                ),
            generation: snapshot.generation,
            admitted_connections: admission.in_flight(crate::runtime::AdmissionKind::Connection),
            replay_entries: admission.in_flight(crate::runtime::AdmissionKind::ReplayEntry)
                + runtime
                    .listener_replays
                    .handoff
                    .values()
                    .map(|cache| cache.entry_count() as u64)
                    .sum::<u64>()
                + runtime
                    .listener_replays
                    .nxr
                    .values()
                    .map(|cache| cache.entry_count() as u64)
                    .sum::<u64>(),
            fd_units_in_use: runtime.fd_budget.in_use(),
            retained_pipe_pairs,
            retained_pipe_bytes,
            warm_ready,
            warm_connecting,
        },
    );
}

/// Builds the adaptive soft-ceiling controller when the tuning mode selects one.
///
/// The controller exists only under `adaptive`: under `startup` no controller
/// is built and nothing ever adjusts a ceiling or the dial rate. Its bounds
/// come from the effective startup policy, so every hard bound is exactly the
/// value the pools were constructed with.
pub(super) fn adaptive_controller(
    node: &NodeConfig,
    policy: &EffectivePolicy,
    authorities: &ProcessAuthorities,
    pressure: &PressureGauge,
) -> Option<adaptive::AdaptiveController> {
    let runtime = node.runtime();
    (runtime.tuning() == TuningMode::Adaptive).then(|| {
        adaptive::AdaptiveController::new(
            authorities.governor.clone(),
            authorities.direct_barrier.clone(),
            pressure.clone(),
            policy,
            runtime.status_file.clone(),
        )
    })
}

/// Runs the adaptive controller until shutdown.
///
/// One tick every five seconds, driven by the same cancellable
/// sleep-or-shutdown pattern as the resource monitor; the loop holds no
/// lock across an await, so shutdown is never delayed. Observability is
/// transition-based: exactly one structured event per knob change, and the
/// status file (when `runtime.statusFile` is set) is rewritten at startup
/// and whenever a ceiling or the pressure state changed — never per tick.
pub(super) async fn run_adaptive_controller(
    runtime: Arc<RuntimeStore>,
    mut controller: adaptive::AdaptiveController,
    mut shutdown: watch::Receiver<bool>,
) {
    // Publish the initial snapshot so the status file describes a running
    // controller before its first transition, not an empty file.
    write_adaptive_status(&runtime, &controller);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = time::sleep(adaptive::TICK_INTERVAL) => {}
        }
        if *shutdown.borrow() {
            break;
        }
        let now = adaptive::unix_millis();
        let outcome = controller.tick(now);
        if outcome.changes.is_empty() && !outcome.pressure_changed {
            continue;
        }
        let snapshot = runtime.load();
        for change in &outcome.changes {
            emit(
                &snapshot.logger,
                &LogEvent::AdaptiveCeilingChanged {
                    knob: change.knob.name(),
                    reason: change.reason.as_str(),
                    from: change.from,
                    to: change.to,
                    floor: change.floor,
                    ceiling: change.ceiling,
                },
            );
        }
        drop(snapshot);
        write_adaptive_status(&runtime, &controller);
    }
}

/// Rewrites the status file, logging a bounded warning on failure.
fn write_adaptive_status(runtime: &Arc<RuntimeStore>, controller: &adaptive::AdaptiveController) {
    if let Err(error) = controller.write_status(adaptive::unix_millis()) {
        let snapshot = runtime.load();
        emit(
            &snapshot.logger,
            &LogEvent::AdaptiveStatusWriteFailed {
                path: controller
                    .status_file()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                error: error.to_string(),
            },
        );
    }
}

pub(super) async fn run_network_refresh(
    environment: NetworkEnvironment,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = time::sleep(interval) => environment.refresh_routes(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io, time::Duration};

    use tokio::{sync::oneshot, time};

    use super::adaptive_controller;
    use crate::{
        config::node::fixture,
        server::production::{ProductionServer, fixture::unused_loopback_port},
    };

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn idle_landing_replay_entries_are_reclaimed_without_another_admission() {
        use crate::{protocol::handoff::HandoffReplayCache, server::nxr::NxrReplayCache};
        use std::sync::Arc;
        use tokio::sync::watch;
        for memory_enabled in [false, true] {
            let config = crate::server::production::fixture::entry_config(unused_loopback_port());
            let mut server = ProductionServer::from_config(config).unwrap();
            let handoff = HandoffReplayCache::new(8, Duration::from_nanos(1)).unwrap();
            let nxr = NxrReplayCache::new(8, Duration::from_nanos(1)).unwrap();
            handoff.reserve([1; 16]).unwrap();
            nxr.reserve([2; 16]).unwrap();
            assert_eq!(handoff.entry_count(), 1);
            assert_eq!(nxr.entry_count(), 1);
            let runtime = Arc::get_mut(&mut server.runtime).unwrap();
            let address = "127.0.0.1:1".parse().unwrap();
            runtime
                .listener_replays
                .handoff
                .insert(address, handoff.clone());
            runtime.listener_replays.nxr.insert(address, nxr.clone());
            let memory = super::MemoryWatch {
                sampler: crate::runtime::machine::MachineReport::conservative().memory_sampler(),
                plan: crate::runtime::machine::MemoryPlan::derive(1_073_741_824).unwrap(),
            };
            let (stop, shutdown) = watch::channel(false);
            let task = tokio::spawn(super::run_resource_monitor(
                server.runtime.clone(),
                memory_enabled.then_some(memory),
                shutdown,
            ));
            tokio::task::yield_now().await;
            time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
            stop.send(true).unwrap();
            task.await.unwrap();
            assert_eq!(
                handoff.entry_count(),
                0,
                "idle Handoff expiry must release occupancy"
            );
            assert_eq!(
                nxr.entry_count(),
                0,
                "idle NXR expiry must release occupancy"
            );
        }
    }

    #[test]
    fn the_adaptive_controller_is_built_only_in_adaptive_mode() {
        for (mode, expect_controller) in [("startup", false), ("adaptive", true)] {
            // A status file is meaningful only under `adaptive`, and
            // validation says so, so the fixture states one only there.
            let status = if mode == "adaptive" {
                r#", "statusFile": "/run/rust-reality/status.json""#
            } else {
                ""
            };
            let config = fixture::validated(&fixture::entry_without_routing(&format!(
                r#""listeners": [{{ "port": 8443, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "tuning": "{mode}"{status} }}"#
            )));
            let server = ProductionServer::from_config(config).expect("server must compile");
            let snapshot = server.runtime.load();
            let controller = adaptive_controller(
                &snapshot.node,
                &server.runtime.policy,
                &server.runtime.authorities,
                &server.runtime.pressure,
            );
            assert_eq!(
                controller.is_some(),
                expect_controller,
                "mode {mode} must select the controller only when adaptive"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn adaptive_mode_publishes_a_status_file_and_shuts_down_cleanly() {
        let port = unused_loopback_port();
        let directory = std::env::temp_dir().join(format!(
            "rust-reality-adaptive-server-{}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("test clock must be valid")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("temporary directory must be created");
        let status_path = directory.join("status.json");
        let config = fixture::validated(&fixture::entry_without_routing(&format!(
            r#""listeners": [{{ "port": {port}, "ip": "ipv4Only", "ipv4": "127.0.0.1" }}],
  "routing": {{ "default": "direct" }},
  "runtime": {{ "tuning": "adaptive", "statusFile": "{}" }}"#,
            status_path.display()
        )));
        let server = ProductionServer::from_config(config).expect("server must compile");
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server_task = tokio::spawn(server.run_until(async move {
            shutdown_receiver
                .await
                .map_err(|_| io::Error::other("test shutdown sender dropped"))
        }));

        time::timeout(Duration::from_secs(5), async {
            while !status_path.exists() {
                time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the controller must publish its initial status snapshot");
        let status =
            crate::runtime::adaptive::read_status(&status_path).expect("the snapshot must parse");
        assert_eq!(status.schema_version, 1);
        assert_eq!(status.pressure, "normal");
        assert_eq!(status.knobs.len(), 8);
        assert!(
            status
                .knobs
                .iter()
                .all(|knob| knob.value == knob.ceiling && knob.last_change.is_none()),
            "before any tick every knob sits at its startup-derived ceiling"
        );

        shutdown_sender.send(()).expect("shutdown must send");
        time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the controller task must not hang shutdown")
            .expect("server task must not panic")
            .expect("server must stop cleanly");
        std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
    }
}
