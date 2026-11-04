use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Wake, Waker},
    time::Duration,
};

use crate::{
    runtime::{ResourceGovernor, policy::ResourceGovernorPolicy},
    transport::{FdBudget, TcpRelay, TcpRelayConfig},
};

use super::{
    CoverHandshakePlan, CoverHandshakeRecordShape, CoverProfileState, CoverProfiles,
    LIFECYCLE_ACTIVE, LIFECYCLE_CREATED, MAX_PROFILE_CLASSES, RealityFallback,
    collection_capacity_available, derive_profile_state, first_encrypted_record_range, lock,
    profile_is_current, run_collector,
};

fn test_profiles() -> CoverProfiles {
    let policy = ResourceGovernorPolicy::default();
    let governor = ResourceGovernor::new(&policy);
    let relay = TcpRelay::new(TcpRelayConfig::for_test(), FdBudget::new(4_096))
        .expect("test relay must build");
    let fallback = RealityFallback::new("127.0.0.1:1", governor.clone(), &policy, relay);
    CoverProfiles::new(23, fallback, governor, Duration::from_secs(1))
}

#[test]
fn cached_nomination_avoids_probe_template_allocations() {
    let profiles = test_profiles();
    profiles
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let (hello, profile) = super::CoverProfile::controlled_test_observation();
    let template = hello.controlled_cover_probe_template().expect("template");
    super::publish(
        &profiles.inner,
        super::Candidate {
            class: template.class(),
            template,
        },
        profile,
    );
    profiles.nominate(&hello); // Warm this thread's ArcSwap bookkeeping.
    let classify = allocation_counter::measure(|| {
        std::hint::black_box(hello.normalized_profile_class().expect("class"));
    });
    let nominate = allocation_counter::measure(|| profiles.nominate(&hello));
    eprintln!(
        "cached nominate bytes={} count={}; classify bytes={} count={}",
        nominate.bytes_total, nominate.count_total, classify.bytes_total, classify.count_total
    );
    assert_eq!(
        nominate.bytes_total, classify.bytes_total,
        "a current profile needs classification but no probe template"
    );
    assert_eq!(nominate.count_total, classify.count_total);
    assert!(lock(&profiles.inner.queue).candidates.is_empty());
}

#[test]
fn expired_profile_nomination_still_queues_a_controlled_probe() {
    let profiles = test_profiles();
    profiles
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let (hello, profile) = super::CoverProfile::controlled_test_observation();
    let template = hello.controlled_cover_probe_template().expect("template");
    let class = template.class();
    super::publish(
        &profiles.inner,
        super::Candidate { class, template },
        profile,
    );
    let mut expired = profiles.inner.published.load().as_ref().clone();
    expired[0].expires_at = tokio::time::Instant::now() - Duration::from_secs(1);
    profiles.inner.published.store(Arc::new(expired));
    profiles.nominate(&hello);
    let queue = lock(&profiles.inner.queue);
    assert_eq!(queue.candidates.len(), 1);
    assert_eq!(queue.candidates[0].class, class);
    assert_eq!(queue.candidates[0].template.class(), class);
}

#[test]
fn missing_profile_nomination_preserves_collection_and_retirement() {
    let profiles = test_profiles();
    profiles
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let (hello, _) = super::CoverProfile::controlled_test_observation();
    profiles.nominate(&hello);
    assert_eq!(lock(&profiles.inner.queue).candidates.len(), 1);
    profiles.nominate(&hello);
    assert_eq!(lock(&profiles.inner.queue).candidates.len(), 1);
    assert!(profiles.deactivate());
    profiles.nominate(&hello);
    assert!(lock(&profiles.inner.queue).candidates.is_empty());
}

#[test]
fn cold_nomination_does_not_repeat_classification_allocations() {
    let reference = test_profiles();
    let candidate = test_profiles();
    reference
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    candidate
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let (hello, _) = super::CoverProfile::controlled_test_observation();
    drop(reference.inner.published.load());
    drop(candidate.inner.published.load());
    let before = allocation_counter::measure(|| {
        let template = hello.controlled_cover_probe_template().expect("template");
        super::enqueue(&reference.inner, template, tokio::time::Instant::now());
    });
    let after = allocation_counter::measure(|| candidate.nominate(&hello));
    assert_eq!(after.bytes_total, before.bytes_total);
    assert_eq!(after.count_total, before.count_total);
    assert_eq!(lock(&candidate.inner.queue).candidates.len(), 1);
}

#[derive(Default)]
struct WakeFlag(AtomicBool);

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

#[test]
fn collector_retirement_between_empty_queue_and_wait_releases_generation() {
    let profiles = test_profiles();
    profiles
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let retired = Arc::downgrade(&profiles.inner);
    let retiring_profiles = profiles.clone();
    // Force retirement after the collector checked ACTIVE and observed an
    // empty queue, before it constructs its notification future.
    *lock(&profiles.inner.before_idle_wait) = Some(Box::new(move || {
        assert!(retiring_profiles.deactivate());
    }));
    let mut collector = Box::pin(run_collector(Arc::clone(&profiles.inner)));
    drop(profiles);

    assert!(
        collector
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready(),
        "retirement before waiter registration must not strand the collector"
    );
    assert!(
        retired.upgrade().is_none(),
        "the completed collector must release its generation before being dropped"
    );
}

#[test]
fn idle_collector_retirement_wakes_and_releases_generation() {
    let profiles = test_profiles();
    profiles
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let retired = Arc::downgrade(&profiles.inner);
    let wake = Arc::new(WakeFlag::default());
    let waker = Waker::from(Arc::clone(&wake));
    let mut context = Context::from_waker(&waker);
    let mut collector = Box::pin(run_collector(Arc::clone(&profiles.inner)));
    assert!(collector.as_mut().poll(&mut context).is_pending());
    assert!(!wake.0.load(Ordering::Acquire));

    assert!(profiles.deactivate());
    assert!(!profiles.deactivate(), "retirement must remain idempotent");
    assert!(
        wake.0.load(Ordering::Acquire),
        "retirement must wake the task"
    );
    drop(profiles);
    assert!(collector.as_mut().poll(&mut context).is_ready());
    assert!(retired.upgrade().is_none());
}

#[test]
fn collector_retired_before_first_poll_releases_generation() {
    let profiles = test_profiles();
    profiles
        .inner
        .lifecycle
        .store(LIFECYCLE_ACTIVE, Ordering::Release);
    let retired = Arc::downgrade(&profiles.inner);
    let mut collector = Box::pin(run_collector(Arc::clone(&profiles.inner)));
    assert!(profiles.deactivate());
    assert!(!profiles.activate(), "a retired generation cannot restart");
    drop(profiles);

    assert!(
        collector
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    assert!(retired.upgrade().is_none());
}

#[test]
fn a_full_cache_can_refresh_but_cannot_admit_a_new_class() {
    assert!(collection_capacity_available(MAX_PROFILE_CLASSES, 0, true));
    assert!(!collection_capacity_available(
        MAX_PROFILE_CLASSES,
        0,
        false
    ));
    assert!(!collection_capacity_available(
        MAX_PROFILE_CLASSES - 1,
        1,
        false
    ));
}

#[test]
fn locates_first_encrypted_record_with_and_without_compatibility_ccs() {
    let mut prefix = vec![22, 3, 3, 0, 4, 2, 0, 0, 0];
    prefix.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    prefix.extend_from_slice(&[23, 3, 3, 0, 32]);
    assert_eq!(
        first_encrypted_record_range(
            &prefix,
            CoverHandshakePlan {
                emit_ccs: true,
                shape: CoverHandshakeRecordShape::Coalesced { wire_len: 37 },
            },
        ),
        Ok(15..52)
    );
    assert_eq!(
        first_encrypted_record_range(
            &prefix[..9],
            CoverHandshakePlan {
                emit_ccs: false,
                shape: CoverHandshakeRecordShape::PositionalRecords {
                    wire_lens: [37, 42, 43, 44],
                    nst_wire_len: None,
                },
            },
        ),
        Ok(9..46)
    );
}

#[test]
fn aggregate_profile_state_is_closed_and_fail_safe() {
    assert_eq!(
        derive_profile_state(LIFECYCLE_CREATED, false, false, false, false),
        CoverProfileState::Disabled
    );
    assert_eq!(
        derive_profile_state(LIFECYCLE_ACTIVE, false, false, false, false),
        CoverProfileState::Unavailable
    );
    assert_eq!(
        derive_profile_state(LIFECYCLE_ACTIVE, false, true, false, false),
        CoverProfileState::Collecting
    );
    assert_eq!(
        derive_profile_state(LIFECYCLE_ACTIVE, false, false, true, false),
        CoverProfileState::Stale
    );
    assert_eq!(
        derive_profile_state(LIFECYCLE_ACTIVE, false, false, false, true),
        CoverProfileState::Unstable
    );
    assert_eq!(
        derive_profile_state(LIFECYCLE_ACTIVE, true, true, true, true),
        CoverProfileState::Validated
    );
}

#[test]
fn expiration_and_generation_mismatch_are_always_misses() {
    let now = tokio::time::Instant::now();
    assert!(profile_is_current(
        23,
        23,
        now + std::time::Duration::from_secs(1),
        now
    ));
    assert!(!profile_is_current(
        22,
        23,
        now + std::time::Duration::from_secs(1),
        now
    ));
    assert!(!profile_is_current(23, 23, now, now));
}
