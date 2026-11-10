use std::sync::{Arc, atomic::Ordering};

use crate::{
    runtime::AdmissionKind,
    server::production::{
        ProductionServer, RuntimeUpdateError,
        fixture::{
            cold_variant, entry_config, only_listener, outbounds_of, tiny_ceiling_config,
            unused_loopback_port, with_extra_outbound, with_extra_rule,
        },
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
    let reserved = unused_loopback_port();
    let config = entry_config(reserved.port());
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
    let reserved = unused_loopback_port();
    let config = entry_config(reserved.port());
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
    let reserved = unused_loopback_port();
    let config = entry_config(reserved.port());
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
    let reserved = unused_loopback_port();
    let config = entry_config(reserved.port());
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
fn retired_connection_runtime_is_released_after_its_last_connection() {
    let reserved = unused_loopback_port();
    let config = entry_config(reserved.port());
    let server = ProductionServer::from_config(config.clone()).expect("server must compile");
    let snapshot = server.runtime.load();
    let old_snapshot = Arc::downgrade(&snapshot);
    let connection = only_listener(&snapshot);
    let old_runtime = Arc::downgrade(&connection);
    drop(snapshot);

    server
        .runtime
        .publish(with_extra_outbound(
            config.node().listeners()[0].port,
            "replacement",
        ))
        .expect("hot publication must succeed");
    assert!(old_snapshot.upgrade().is_none());
    assert!(old_runtime.upgrade().is_some());
    drop(connection);
    assert!(old_runtime.upgrade().is_none());
}

#[test]
fn retiring_a_generation_deactivates_only_its_own_pre_auth_pool() {
    let reserved = unused_loopback_port();
    let config = entry_config(reserved.port());
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

#[tokio::test(flavor = "current_thread")]
async fn reload_cannot_multiply_the_connection_ceiling() {
    let (_reserved, config) = tiny_ceiling_config();
    let server = ProductionServer::from_config(config).expect("must compile");
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
    let (_reserved, config) = tiny_ceiling_config();
    let server = ProductionServer::from_config(config).expect("must compile");
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
