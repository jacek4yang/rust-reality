//! The three periodic tasks that keep a running generation honest.
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

/// Samples the bounded memory signal and publishes the combined pressure state.
///
/// This is the only place the pressure gauge is written outside tests. It
/// runs on a fixed interval — never in a read, write or record loop — folds
/// the descriptor dimension in from the budget's own hysteresis watermarks,
/// and logs transitions only, so a sustained condition costs two log lines
/// rather than one per second.
pub(super) async fn run_resource_monitor(
    runtime: Arc<RuntimeStore>,
    watch: MemoryWatch,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut memory_state = ResourcePressure::Normal;
    let mut last_usage: Option<u64> = None;
    let mut last_source = watch.sampler.configured_source();
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
        let fd_state = ResourcePressure::from(runtime.fd_budget.pressure());
        if let Some(reading) = watch.sampler.sample() {
            // An unreadable sample keeps the previous state: a monitoring gap
            // must never itself raise or clear an alarm. A sampler that falls
            // back to a different source reports the source actually used,
            // so a fallback can never masquerade as the configured source.
            if reading.source != last_source {
                let snapshot = runtime.load();
                emit(
                    &snapshot.logger,
                    &LogEvent::MemorySamplerChanged {
                        from: last_source.as_str(),
                        to: reading.source.as_str(),
                    },
                );
                last_source = reading.source;
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
