use super::{AdaptiveController, ChangeReason, EffectivePolicy, quantized_step, read_status};
use crate::runtime::policy::{DirectBarrierPolicy, ResourceGovernorPolicy};
use crate::runtime::{
    AdmissionKind, DirectBarrier, PressureGauge, ResourceGovernor, ResourcePressure,
};

/// A policy whose startup values sit above the v1.5 defaults, so every
/// knob has room to move in both directions.
fn test_policy() -> EffectivePolicy {
    EffectivePolicy {
        governor: ResourceGovernorPolicy {
            max_connections: 32_768,
            max_handshakes: 4_096,
            max_fallbacks: 2_048,
            max_crypto_operations: 512,
            max_replay_entries: 131_072,
            max_dns_lookups: 256,
            ..ResourceGovernorPolicy::default()
        },
        direct_barrier: DirectBarrierPolicy {
            max_concurrent: 8_192,
            max_per_second: 16_384,
        },
        ..EffectivePolicy::default()
    }
}

fn test_controller() -> AdaptiveController {
    let policy = test_policy();
    AdaptiveController::new(
        ResourceGovernor::new(&policy.governor),
        DirectBarrier::new(&policy.direct_barrier),
        PressureGauge::new(),
        &policy,
        None,
    )
}

fn tick(controller: &mut AdaptiveController, count: u64) {
    for _ in 0..count {
        controller.tick(1_000);
    }
}

#[test]
fn the_step_is_a_quantized_quarter_of_the_startup_value() {
    assert_eq!(quantized_step(32_768, 64), 8_192);
    assert_eq!(quantized_step(16_384, 16), 4_096);
    assert_eq!(
        quantized_step(100, 64),
        64,
        "the quantum floors the step at small magnitudes"
    );
    assert_eq!(quantized_step(63, 64), 64);
    assert_eq!(quantized_step(262_144, 64), 65_536);
}

#[test]
fn scale_up_waits_for_three_consecutive_high_ticks() {
    let mut controller = test_controller();
    let governor = controller.governor.clone();
    // Lower the connection knob to its floor first so there is room to
    // scale up; the pool ceiling follows.
    controller.knobs[0].value = 16_384;
    governor.set_ceiling(AdmissionKind::Connection, 16_384);
    // 90% utilization of the lowered ceiling (high watermark is 13_926.4).
    let held: Vec<_> = (0..14_800)
        .map(|_| {
            governor
                .try_acquire(AdmissionKind::Connection)
                .expect("below the lowered ceiling")
        })
        .collect();

    tick(&mut controller, 2);
    assert_eq!(
        governor.ceiling(AdmissionKind::Connection),
        16_384,
        "two high ticks must not move the knob"
    );
    tick(&mut controller, 1);
    assert_eq!(
        governor.ceiling(AdmissionKind::Connection),
        24_576,
        "the third consecutive high tick applies one quantized 8_192 step"
    );
    drop(held);
}

#[test]
fn a_tick_between_the_watermarks_resets_the_hysteresis() {
    let mut controller = test_controller();
    let governor = controller.governor.clone();
    controller.knobs[0].value = 16_384;
    governor.set_ceiling(AdmissionKind::Connection, 16_384);
    let mut held: Vec<_> = (0..14_800)
        .map(|_| {
            governor
                .try_acquire(AdmissionKind::Connection)
                .expect("below the lowered ceiling")
        })
        .collect();
    tick(&mut controller, 2);
    // Drop to 50% utilization: between the watermarks, counters reset.
    drop(held.drain(..6_600));
    tick(&mut controller, 1);
    // Return above the high watermark: the counter restarts from zero.
    held.extend((0..6_600).map(|_| {
        governor
            .try_acquire(AdmissionKind::Connection)
            .expect("below the lowered ceiling")
    }));
    tick(&mut controller, 2);
    assert_eq!(
        governor.ceiling(AdmissionKind::Connection),
        16_384,
        "the interrupted run of high ticks must not scale up"
    );
    tick(&mut controller, 1);
    assert_eq!(
        governor.ceiling(AdmissionKind::Connection),
        24_576,
        "three fresh consecutive high ticks scale up"
    );
    drop(held);
}

#[test]
fn scale_down_waits_for_six_consecutive_low_ticks() {
    let mut controller = test_controller();
    // No permits held: utilization is 0%, below the low watermark.
    tick(&mut controller, 5);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        32_768,
        "five low ticks must not move the knob"
    );
    tick(&mut controller, 1);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        24_576,
        "the sixth low tick applies one quantized 8_192 step down"
    );
}

#[test]
fn the_dwell_blocks_a_second_change_for_thirty_seconds() {
    let mut controller = test_controller();
    // First change lands at tick 6; the next may land no earlier than
    // tick 12 even though the low signal persists.
    tick(&mut controller, 6);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        24_576
    );
    tick(&mut controller, 5);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        24_576,
        "the dwell suppresses a second change inside 30 s"
    );
    tick(&mut controller, 1);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        16_384,
        "the deferred change lands once the dwell elapses"
    );
}

#[test]
fn the_floor_stops_the_walk_at_the_responsive_minimum() {
    let mut controller = test_controller();
    // Walk all the way down: 16_384 of headroom in 8_192 steps needs two
    // changes, six ticks apart each; extra ticks must not undercut the
    // floor.
    tick(&mut controller, 30);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        16_384,
        "the v1.5 default is the floor"
    );
    assert!(
        controller.tick(1_000).changes.is_empty(),
        "a knob resting on its floor never latches a pending move"
    );
}

#[test]
fn critical_pressure_clamps_every_knob_to_the_floor_in_one_tick() {
    let mut controller = test_controller();
    let pressure = controller.pressure.clone();
    // Dwell must not protect the walk: cause a normal change first, then
    // go critical immediately afterwards.
    tick(&mut controller, 6);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        24_576
    );
    pressure.set(ResourcePressure::Critical);
    let outcome = controller.tick(2_000);
    assert_eq!(outcome.changes.len(), 8, "every knob moves in one tick");
    assert!(
        outcome
            .changes
            .iter()
            .all(|change| change.reason == ChangeReason::CriticalPressure)
    );
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::Connection),
        16_384
    );
    assert_eq!(controller.governor.ceiling(AdmissionKind::Handshake), 1_024);
    assert_eq!(controller.governor.ceiling(AdmissionKind::Fallback), 512);
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::CryptoOperation),
        128
    );
    assert_eq!(
        controller.governor.ceiling(AdmissionKind::ReplayEntry),
        65_536
    );
    assert_eq!(controller.governor.ceiling(AdmissionKind::DnsLookup), 64);
    assert_eq!(controller.direct_barrier.concurrency_ceiling(), 2_048);
    assert_eq!(controller.direct_barrier.rate_per_second(), 4_096);
}

#[test]
fn recovery_from_critical_walks_back_up_with_the_normal_hysteresis() {
    let mut controller = test_controller();
    let pressure = controller.pressure.clone();
    let governor = controller.governor.clone();
    pressure.set(ResourcePressure::Critical);
    tick(&mut controller, 1);
    assert_eq!(governor.ceiling(AdmissionKind::Connection), 16_384);
    pressure.set(ResourcePressure::Normal);
    // 90% utilization of the floor: the high watermark of 16_384 is 13_926.4.
    let held: Vec<_> = (0..14_800)
        .map(|_| {
            governor
                .try_acquire(AdmissionKind::Connection)
                .expect("below the floor ceiling")
        })
        .collect();
    tick(&mut controller, 3);
    assert_eq!(
        governor.ceiling(AdmissionKind::Connection),
        16_384,
        "three high ticks trip, but the dwell from the critical clamp still holds"
    );
    tick(&mut controller, 3);
    assert_eq!(
        governor.ceiling(AdmissionKind::Connection),
        24_576,
        "recovery adds one step once hysteresis and dwell both allow"
    );
    drop(held);
}

#[test]
fn the_rate_knob_follows_dial_demand_with_the_rate_quantum() {
    let mut controller = test_controller();
    let barrier = controller.direct_barrier.clone();
    // 90% of the 8_192 concurrent-dial startup value.
    let held: Vec<_> = (0..7_400)
        .map(|_| barrier.try_acquire().expect("below the startup ceiling"))
        .collect();
    tick(&mut controller, 3);
    assert_eq!(
        barrier.concurrency_ceiling(),
        8_192,
        "the concurrency knob is at its hard bound"
    );
    // Both knobs are at their hard bounds, so scale down instead.
    drop(held);
    tick(&mut controller, 6);
    assert_eq!(barrier.concurrency_ceiling(), 6_144);
    assert_eq!(
        barrier.rate_per_second(),
        12_288,
        "the rate knob moves with the same demand signal and its own step"
    );
}

#[test]
fn the_status_snapshot_reports_bounds_and_the_last_transition() {
    let mut controller = test_controller();
    tick(&mut controller, 6);
    let status = controller.status(9_000);
    assert_eq!(status.schema_version, 1);
    assert_eq!(status.pressure, "normal");
    assert_eq!(status.knobs.len(), 8);
    let connections = &status.knobs[0];
    assert_eq!(connections.name, "resourceGovernor.maxConnections");
    assert_eq!(connections.value, 24_576);
    assert_eq!(connections.floor, 16_384);
    assert_eq!(connections.ceiling, 32_768);
    let change = connections.last_change.expect("a change was applied");
    assert_eq!(change.reason, ChangeReason::LowUtilization);
    assert_eq!(change.from, 32_768);
    assert_eq!(change.to, 24_576);
    assert_eq!(change.tick, 6);
    // Round-trip through the wire format the CLI consumes.
    let bytes = serde_json::to_vec_pretty(&status).expect("status must serialize");
    let parsed: super::AdaptiveStatus =
        serde_json::from_slice(&bytes).expect("status must deserialize");
    assert_eq!(parsed, status);
}

#[test]
fn the_status_file_is_written_atomically_and_read_back() {
    let directory = std::env::temp_dir().join(format!(
        "rust-reality-adaptive-test-{}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock must be valid")
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).expect("temporary directory must be created");
    let path = directory.join("status.json");

    let policy = test_policy();
    let mut controller = AdaptiveController::new(
        ResourceGovernor::new(&policy.governor),
        DirectBarrier::new(&policy.direct_barrier),
        PressureGauge::new(),
        &policy,
        Some(path.clone()),
    );
    tick(&mut controller, 6);
    controller
        .write_status(9_000)
        .expect("status must be written");

    let status = read_status(&path).expect("the written snapshot must read back");
    assert_eq!(status.updated_at_unix_ms, 9_000);
    assert_eq!(status.knobs[0].value, 24_576);
    assert_eq!(
        status.knobs[0]
            .last_change
            .expect("a change was applied")
            .reason,
        ChangeReason::LowUtilization
    );
    assert_eq!(
        std::fs::read_dir(&directory)
            .expect("directory must list")
            .filter(|entry| entry
                .as_ref()
                .expect("entry must read")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
            .count(),
        0,
        "no temporary file may remain"
    );
    std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
}

#[test]
fn read_status_reports_a_missing_or_invalid_file() {
    let missing = std::path::Path::new("/nonexistent/rust-reality/status.json");
    assert!(matches!(
        read_status(missing),
        Err(super::StatusReadError::Io { .. })
    ));

    let directory = std::env::temp_dir().join(format!(
        "rust-reality-adaptive-invalid-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("temporary directory must be created");
    let path = directory.join("status.json");
    std::fs::write(&path, b"not json").expect("fixture must be written");
    assert!(matches!(
        read_status(&path),
        Err(super::StatusReadError::Invalid { .. })
    ));
    std::fs::remove_dir_all(&directory).expect("temporary directory must be removed");
}

#[test]
fn an_operator_pin_below_the_default_becomes_an_immovable_knob() {
    let mut policy = test_policy();
    policy.governor.max_dns_lookups = 32;
    let controller = AdaptiveController::new(
        ResourceGovernor::new(&policy.governor),
        DirectBarrier::new(&policy.direct_barrier),
        PressureGauge::new(),
        &policy,
        None,
    );
    let status = controller.status(1_000);
    let dns = status
        .knobs
        .iter()
        .find(|knob| knob.name == "resourceGovernor.maxDnsLookups")
        .expect("the dns knob exists");
    assert_eq!(dns.value, 32);
    assert_eq!(dns.floor, 32, "the floor never undercuts an operator pin");
    assert_eq!(dns.ceiling, 32);
}
