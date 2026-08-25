use std::{
    collections::VecDeque,
    ops::Range,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::Duration,
};

use arc_swap::ArcSwap;
use tokio::{sync::Notify, time::Instant};

use crate::{
    protocol::reality::{
        ClientHello, CoverProbeTemplate, NormalizedClientHelloClass,
        tls13::{CoverHandshakePlan, CoverHandshakeRecordShape, CoverProfile},
    },
    runtime::{AdmissionKind, ResourceGovernor},
};

use super::fallback::RealityFallback;

const MAX_PROFILE_CLASSES: usize = 16;
const REQUIRED_CONSENSUS: u8 = 4;
const PROFILE_TTL: Duration = Duration::from_secs(10 * 60);
const PROFILE_TTL_JITTER: Duration = Duration::from_secs(60);
const FAILURE_COOLDOWN: Duration = Duration::from_secs(30);
const UNSTABLE_COOLDOWN: Duration = Duration::from_secs(5 * 60);
const LIFECYCLE_CREATED: u8 = 0;
const LIFECYCLE_ACTIVE: u8 = 1;
const LIFECYCLE_STOPPED: u8 = 2;

/// Bounded generation-local controlled cover-profile collector and cache.
#[derive(Clone)]
pub(crate) struct CoverProfiles {
    inner: Arc<CoverProfilesInner>,
}

struct CoverProfilesInner {
    generation: u64,
    fallback: RealityFallback,
    governor: ResourceGovernor,
    read_timeout: Duration,
    lifecycle: AtomicU8,
    published: ArcSwap<Vec<PublishedProfile>>,
    publication: Mutex<()>,
    queue: Mutex<CollectionQueue>,
    notify: Notify,
    metrics: CoverProfileMetrics,
}

#[derive(Clone)]
struct PublishedProfile {
    class: NormalizedClientHelloClass,
    profile: Arc<CoverProfile>,
    template: CoverProbeTemplate,
    expires_at: Instant,
}

struct Candidate {
    class: NormalizedClientHelloClass,
    template: CoverProbeTemplate,
}

#[derive(Default)]
struct CollectionQueue {
    candidates: VecDeque<Candidate>,
    cooldowns: Vec<(NormalizedClientHelloClass, Instant)>,
}

#[derive(Default)]
struct CoverProfileMetrics {
    hit: AtomicU64,
    miss: AtomicU64,
    stale: AtomicU64,
    unstable: AtomicU64,
    refresh: AtomicU64,
    refresh_failure: AtomicU64,
    disagreement: AtomicU64,
    disabled: AtomicU64,
    collecting: AtomicU32,
    validated: AtomicU32,
}

/// Fixed-cardinality, secret-free state for local diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CoverProfileSnapshot {
    pub(crate) generation: u64,
    pub(crate) hit: u64,
    pub(crate) miss: u64,
    pub(crate) stale: u64,
    pub(crate) unstable: u64,
    pub(crate) refresh: u64,
    pub(crate) refresh_failure: u64,
    pub(crate) disagreement: u64,
    pub(crate) disabled: u64,
    pub(crate) collecting: u32,
    pub(crate) validated: u32,
}

impl CoverProfiles {
    pub(crate) fn new(
        generation: u64,
        fallback: RealityFallback,
        governor: ResourceGovernor,
        read_timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(CoverProfilesInner {
                generation,
                fallback,
                governor,
                read_timeout,
                lifecycle: AtomicU8::new(LIFECYCLE_CREATED),
                published: ArcSwap::from_pointee(Vec::new()),
                publication: Mutex::new(()),
                queue: Mutex::new(CollectionQueue::default()),
                notify: Notify::new(),
                metrics: CoverProfileMetrics::default(),
            }),
        }
    }

    /// Starts one bounded collector task without blocking listener startup.
    pub(crate) fn activate(&self) -> bool {
        if self
            .inner
            .lifecycle
            .compare_exchange(
                LIFECYCLE_CREATED,
                LIFECYCLE_ACTIVE,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.inner
                .lifecycle
                .store(LIFECYCLE_CREATED, Ordering::Release);
            return false;
        };
        runtime.spawn(run_collector(Arc::clone(&self.inner)));
        true
    }

    /// Stops collection and drops every generation-local candidate/profile.
    pub(crate) fn deactivate(&self) -> bool {
        if self
            .inner
            .lifecycle
            .swap(LIFECYCLE_STOPPED, Ordering::AcqRel)
            == LIFECYCLE_STOPPED
        {
            return false;
        }
        let mut queue = lock(&self.inner.queue);
        queue.candidates.clear();
        queue.cooldowns.clear();
        drop(queue);
        let publication = lock(&self.inner.publication);
        self.inner.published.store(Arc::new(Vec::new()));
        drop(publication);
        self.inner.metrics.validated.store(0, Ordering::Release);
        self.inner.notify.notify_waiters();
        true
    }

    /// Returns a validated, unexpired exact-class profile without network I/O.
    pub(crate) fn lookup(&self, hello: &ClientHello) -> Option<Arc<CoverProfile>> {
        if self.inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            self.inner.metrics.disabled.fetch_add(1, Ordering::Relaxed);
            self.inner.metrics.miss.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let Ok(class) = hello.normalized_profile_class() else {
            self.inner.metrics.miss.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        let now = Instant::now();
        let published = self.inner.published.load();
        if let Some(entry) = published.iter().find(|entry| entry.class == class) {
            if entry.expires_at > now {
                return Some(Arc::clone(&entry.profile));
            }
            self.inner.metrics.stale.fetch_add(1, Ordering::Relaxed);
            enqueue(&self.inner, entry.template.clone(), now);
        }
        self.inner.metrics.miss.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub(crate) fn record_hit(&self) {
        self.inner.metrics.hit.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomically removes a profile that could not reproduce the current
    /// authenticated flight. The same connection immediately uses live cover;
    /// only later controlled consensus can republish the class.
    pub(crate) fn invalidate(&self, hello: &ClientHello) {
        let Ok(class) = hello.normalized_profile_class() else {
            return;
        };
        let publication = lock(&self.inner.publication);
        let current = self.inner.published.load();
        if !current.iter().any(|entry| entry.class == class) {
            return;
        }
        let mut replacement = current.as_ref().clone();
        replacement.retain(|entry| entry.class != class);
        self.inner.published.store(Arc::new(replacement));
        self.inner
            .metrics
            .disagreement
            .fetch_add(1, Ordering::Relaxed);
        self.inner.metrics.validated.store(
            u32::try_from(self.inner.published.load().len()).unwrap_or(u32::MAX),
            Ordering::Release,
        );
        drop(publication);
        cooldown(&self.inner, class, UNSTABLE_COOLDOWN);
    }

    /// Admits one sanitized class only after ClientFinished and replay commit.
    /// Authenticated user traffic nominates a bounded class, but controlled
    /// cover probes alone determine the published semantics.
    pub(crate) fn nominate(&self, hello: &ClientHello) {
        if self.inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            return;
        }
        let Ok(template) = hello.controlled_cover_probe_template() else {
            return;
        };
        enqueue(&self.inner, template, Instant::now());
    }

    pub(crate) fn snapshot(&self) -> CoverProfileSnapshot {
        CoverProfileSnapshot {
            generation: self.inner.generation,
            hit: self.inner.metrics.hit.load(Ordering::Relaxed),
            miss: self.inner.metrics.miss.load(Ordering::Relaxed),
            stale: self.inner.metrics.stale.load(Ordering::Relaxed),
            unstable: self.inner.metrics.unstable.load(Ordering::Relaxed),
            refresh: self.inner.metrics.refresh.load(Ordering::Relaxed),
            refresh_failure: self.inner.metrics.refresh_failure.load(Ordering::Relaxed),
            disagreement: self.inner.metrics.disagreement.load(Ordering::Relaxed),
            disabled: self.inner.metrics.disabled.load(Ordering::Relaxed),
            collecting: self.inner.metrics.collecting.load(Ordering::Acquire),
            validated: self.inner.metrics.validated.load(Ordering::Acquire),
        }
    }
}

fn enqueue(inner: &Arc<CoverProfilesInner>, template: CoverProbeTemplate, now: Instant) {
    let class = template.class();
    if inner
        .published
        .load()
        .iter()
        .any(|entry| entry.class == class && entry.expires_at > now)
    {
        return;
    }
    let mut queue = lock(&inner.queue);
    queue.cooldowns.retain(|(_, until)| *until > now);
    if queue
        .cooldowns
        .iter()
        .any(|(cooldown_class, _)| *cooldown_class == class)
        || queue
            .candidates
            .iter()
            .any(|candidate| candidate.class == class)
        || queue.candidates.len() >= MAX_PROFILE_CLASSES
    {
        return;
    }
    let known = inner.published.load().len();
    if known.saturating_add(queue.candidates.len()) >= MAX_PROFILE_CLASSES {
        return;
    }
    queue.candidates.push_back(Candidate { class, template });
    drop(queue);
    inner.notify.notify_one();
}

async fn run_collector(inner: Arc<CoverProfilesInner>) {
    loop {
        if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            break;
        }
        let candidate = lock(&inner.queue).candidates.pop_front();
        let Some(candidate) = candidate else {
            inner.notify.notified().await;
            continue;
        };
        inner.metrics.collecting.fetch_add(1, Ordering::AcqRel);
        let result = collect_consensus(&inner, &candidate).await;
        inner.metrics.collecting.fetch_sub(1, Ordering::AcqRel);
        match result {
            Ok(profile) => publish(&inner, candidate, profile),
            Err(CollectionFailure::Unstable) => {
                inner.metrics.unstable.fetch_add(1, Ordering::Relaxed);
                inner.metrics.disagreement.fetch_add(1, Ordering::Relaxed);
                cooldown(&inner, candidate.class, UNSTABLE_COOLDOWN);
            }
            Err(CollectionFailure::Unavailable) => {
                inner
                    .metrics
                    .refresh_failure
                    .fetch_add(1, Ordering::Relaxed);
                cooldown(&inner, candidate.class, FAILURE_COOLDOWN);
            }
        }
    }
}

enum CollectionFailure {
    Unavailable,
    Unstable,
}

async fn collect_consensus(
    inner: &CoverProfilesInner,
    candidate: &Candidate,
) -> Result<CoverProfile, CollectionFailure> {
    let mut consensus = None;
    for variant in 0..REQUIRED_CONSENSUS {
        if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
            return Err(CollectionFailure::Unavailable);
        }
        // Fail-fast background admission gives active work priority and creates
        // no attacker-controlled wait queue.
        let _permit = inner
            .governor
            .try_acquire(AdmissionKind::CryptoOperation)
            .map_err(|_| CollectionFailure::Unavailable)?;
        let probe = candidate
            .template
            .generate(variant)
            .map_err(|_| CollectionFailure::Unavailable)?;
        let mut cover = inner
            .fallback
            .profile_probe(probe.wire_record())
            .await
            .map_err(|_| CollectionFailure::Unavailable)?;
        let target_flight = cover
            .read_server_flight(probe.hello(), inner.read_timeout)
            .await
            .map_err(|_| CollectionFailure::Unavailable)?;
        let (target, plan, mut prefix) = target_flight.into_parts();
        let encrypted = first_encrypted_record_range(&prefix, plan)
            .map_err(|_| CollectionFailure::Unavailable)?;
        if prefix.len() < encrypted.end {
            cover
                .complete_prefix(&mut prefix, encrypted.end, inner.read_timeout)
                .await
                .map_err(|_| CollectionFailure::Unavailable)?;
        }
        let first_record = prefix
            .get(encrypted)
            .ok_or(CollectionFailure::Unavailable)?;
        let observed = CoverProfile::from_controlled_observation(
            candidate.class,
            &probe,
            target,
            plan,
            first_record,
        )
        .map_err(|_| CollectionFailure::Unavailable)?;
        match &consensus {
            None => consensus = Some(observed),
            Some(expected) if expected == &observed => {}
            Some(_) => return Err(CollectionFailure::Unstable),
        }
    }
    consensus.ok_or(CollectionFailure::Unavailable)
}

fn first_encrypted_record_range(
    prefix: &[u8],
    plan: CoverHandshakePlan,
) -> Result<Range<usize>, ()> {
    let header = prefix.get(..5).ok_or(())?;
    if header[0] != 22 {
        return Err(());
    }
    let server_hello_wire = 5_usize
        .checked_add(usize::from(u16::from_be_bytes([header[3], header[4]])))
        .ok_or(())?;
    let encrypted_start = server_hello_wire
        .checked_add(if plan.emit_ccs { 6 } else { 0 })
        .ok_or(())?;
    let wire_len = match plan.shape {
        CoverHandshakeRecordShape::Coalesced { wire_len }
        | CoverHandshakeRecordShape::PositionalRecords {
            wire_lens: [wire_len, ..],
            ..
        } => wire_len,
    };
    let encrypted_end = encrypted_start.checked_add(wire_len).ok_or(())?;
    Ok(encrypted_start..encrypted_end)
}

fn publish(inner: &CoverProfilesInner, candidate: Candidate, profile: CoverProfile) {
    if inner.lifecycle.load(Ordering::Acquire) != LIFECYCLE_ACTIVE {
        return;
    }
    let now = Instant::now();
    let publication = lock(&inner.publication);
    let mut profiles = inner.published.load().as_ref().clone();
    profiles.retain(|entry| entry.class != candidate.class);
    if profiles.len() >= MAX_PROFILE_CLASSES {
        return;
    }
    profiles.push(PublishedProfile {
        class: candidate.class,
        profile: Arc::new(profile),
        template: candidate.template,
        expires_at: now + jittered_ttl(),
    });
    inner.published.store(Arc::new(profiles));
    inner.metrics.refresh.fetch_add(1, Ordering::Relaxed);
    inner.metrics.validated.store(
        u32::try_from(inner.published.load().len()).unwrap_or(u32::MAX),
        Ordering::Release,
    );
    drop(publication);
}

fn cooldown(inner: &CoverProfilesInner, class: NormalizedClientHelloClass, duration: Duration) {
    let mut queue = lock(&inner.queue);
    if queue.cooldowns.len() >= MAX_PROFILE_CLASSES {
        queue.cooldowns.remove(0);
    }
    queue.cooldowns.push((class, Instant::now() + duration));
}

fn jittered_ttl() -> Duration {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return PROFILE_TTL;
    }
    let spread = PROFILE_TTL_JITTER.as_secs().saturating_mul(2).max(1);
    let offset = u64::from_le_bytes(bytes) % spread;
    PROFILE_TTL
        .saturating_sub(PROFILE_TTL_JITTER)
        .saturating_add(Duration::from_secs(offset))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::{CoverHandshakePlan, CoverHandshakeRecordShape, first_encrypted_record_range};

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
}
