//! Combined resource-pressure state shared by the listener and admission.
//!
//! # Design
//!
//! Two pressure dimensions feed one effective state: the descriptor budget
//! ([`FdPressure`], with its own enter/exit watermarks inside [`FdBudget`])
//! and, in dedicated resource mode, a memory monitor sampling cgroup
//! `memory.current` on a bounded interval. The effective state is the worst
//! of the dimensions, published here as one atomic value.
//!
//! The gauge is process-lifetime and lock-free: one atomic load on the
//! admission fast path, one `Notify` for the paused listener, and a
//! transition counter that bounds how many pressure log lines an operator
//! can ever see. In standard resource mode nothing ever calls
//! [`PressureGauge::set`], the state stays `Normal`, and every gate that
//! consults the gauge is a no-op — which is what keeps standard-mode
//! behavior identical to before this module existed.

use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};

use tokio::sync::Notify;

use super::admission::AdmissionKind;
use super::fd_budget::FdPressure;

/// The effective process resource-pressure state.
///
/// The variants are ordered, so `max` yields the worse of two states.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResourcePressure {
    /// Capacity is available; all categories are admitted.
    #[default]
    Normal,
    /// New unauthenticated setup and fallback work are refused; established
    /// authenticated relays and ordinary relay traffic continue.
    Pressure,
    /// Accept of new connections and new outbound connects pause; established
    /// traffic, release paths and shutdown stay responsive.
    Critical,
}

impl ResourcePressure {
    /// Returns the stable identifier used in logs and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Pressure => "pressure",
            Self::Critical => "critical",
        }
    }

    /// Returns whether this state admits a new permit of `kind`.
    ///
    /// The ordering is deliberate: fallback work is refused first, then new
    /// unauthenticated handshakes, and only at `Critical` is every new
    /// category paused. Permits already held are never affected, so
    /// established sessions keep their capacity on every path.
    #[must_use]
    pub(crate) const fn admits(self, kind: AdmissionKind) -> bool {
        match self {
            Self::Normal => true,
            Self::Pressure => !matches!(kind, AdmissionKind::Handshake | AdmissionKind::Fallback),
            Self::Critical => false,
        }
    }
}

impl From<FdPressure> for ResourcePressure {
    fn from(state: FdPressure) -> Self {
        match state {
            FdPressure::Normal => Self::Normal,
            // Descriptor exhaustion pauses new setup; the budget itself
            // provides the hard block, so the descriptor dimension never
            // needs to claim the Critical tier.
            FdPressure::High => Self::Pressure,
        }
    }
}

const NORMAL: u8 = 0;
const PRESSURE: u8 = 1;
const CRITICAL: u8 = 2;

const fn encode(state: ResourcePressure) -> u8 {
    match state {
        ResourcePressure::Normal => NORMAL,
        ResourcePressure::Pressure => PRESSURE,
        ResourcePressure::Critical => CRITICAL,
    }
}

const fn decode(value: u8) -> ResourcePressure {
    match value {
        PRESSURE => ResourcePressure::Pressure,
        CRITICAL => ResourcePressure::Critical,
        _ => ResourcePressure::Normal,
    }
}

#[derive(Default)]
struct GaugeInner {
    state: AtomicU8,
    changed: Notify,
    transitions: AtomicU64,
}

/// A lock-free, process-lifetime publication point for [`ResourcePressure`].
#[derive(Clone, Default)]
pub struct PressureGauge {
    inner: Arc<GaugeInner>,
}

impl PressureGauge {
    /// Creates a gauge in the `Normal` state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the current effective state. One relaxed-adjacent atomic load.
    #[must_use]
    pub fn state(&self) -> ResourcePressure {
        decode(self.inner.state.load(Ordering::Acquire))
    }

    /// Returns how many times the effective state changed.
    ///
    /// Pressure logging is transition-based, so this doubles as the bound on
    /// how many pressure lines an operator can ever see.
    #[must_use]
    pub fn transitions(&self) -> u64 {
        self.inner.transitions.load(Ordering::Relaxed)
    }

    /// Publishes a new effective state, returning whether it changed.
    ///
    /// Called by the pressure monitor, and directly by tests. A change wakes
    /// any listener parked in [`Self::wait_while_critical`].
    pub fn set(&self, state: ResourcePressure) -> bool {
        let previous = self.inner.state.swap(encode(state), Ordering::AcqRel);
        if previous == encode(state) {
            return false;
        }
        self.inner.transitions.fetch_add(1, Ordering::Relaxed);
        self.inner.changed.notify_waiters();
        true
    }

    /// Waits until the effective state drops below `Critical`.
    ///
    /// Returns immediately in any other state. `Notify` registers a `Notified`
    /// lazily at its first poll and `notify_waiters` stores no permit, so the
    /// waiter is registered eagerly with `enable` *before* the state re-check:
    /// a transition landing between the failed check and the wait then still
    /// wakes it. There is no poll loop.
    pub async fn wait_while_critical(&self) {
        while self.state() == ResourcePressure::Critical {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.state() != ResourcePressure::Critical {
                break;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PressureGauge, ResourcePressure};
    use crate::runtime::AdmissionKind;

    #[test]
    fn pressure_refuses_fallback_before_handshake_before_connection() {
        for kind in [
            AdmissionKind::Connection,
            AdmissionKind::Handshake,
            AdmissionKind::Fallback,
            AdmissionKind::CryptoOperation,
            AdmissionKind::ReplayEntry,
        ] {
            assert!(ResourcePressure::Normal.admits(kind));
        }

        assert!(
            !ResourcePressure::Pressure.admits(AdmissionKind::Fallback),
            "fallback work is refused first"
        );
        assert!(
            !ResourcePressure::Pressure.admits(AdmissionKind::Handshake),
            "new unauthenticated setup is refused under pressure"
        );
        assert!(ResourcePressure::Pressure.admits(AdmissionKind::Connection));
        assert!(ResourcePressure::Pressure.admits(AdmissionKind::CryptoOperation));

        for kind in [
            AdmissionKind::Connection,
            AdmissionKind::Handshake,
            AdmissionKind::Fallback,
            AdmissionKind::CryptoOperation,
            AdmissionKind::ReplayEntry,
        ] {
            assert!(
                !ResourcePressure::Critical.admits(kind),
                "critical pauses every new category"
            );
        }
    }

    #[test]
    fn the_worse_dimension_wins() {
        assert_eq!(
            ResourcePressure::Normal.max(ResourcePressure::Pressure),
            ResourcePressure::Pressure
        );
        assert_eq!(
            ResourcePressure::Pressure.max(ResourcePressure::Critical),
            ResourcePressure::Critical
        );
    }

    #[test]
    fn set_reports_only_real_transitions() {
        let gauge = PressureGauge::new();
        assert!(!gauge.set(ResourcePressure::Normal));
        assert!(gauge.set(ResourcePressure::Pressure));
        assert!(!gauge.set(ResourcePressure::Pressure));
        assert!(gauge.set(ResourcePressure::Critical));
        assert_eq!(gauge.transitions(), 2);
        assert_eq!(gauge.state(), ResourcePressure::Critical);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_critical_waiter_is_woken_by_a_transition() {
        let gauge = PressureGauge::new();
        gauge.set(ResourcePressure::Critical);
        let waiter = {
            let gauge = gauge.clone();
            tokio::spawn(async move { gauge.wait_while_critical().await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "the waiter must stay parked");
        gauge.set(ResourcePressure::Pressure);
        tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
            .await
            .expect("a transition below critical must wake the waiter")
            .expect("the waiting task must not panic");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_non_critical_state_never_waits() {
        let gauge = PressureGauge::new();
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            gauge.wait_while_critical(),
        )
        .await
        .expect("a normal gauge must not wait");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rapid_transitions_never_strand_a_waiter() {
        // Regression test for the lost-wakeup race: `Notify` registers a
        // `Notified` lazily at first poll and `notify_waiters` stores no
        // permit, so without eager registration a Critical->Normal transition
        // landing between the state re-check and the first poll was missed
        // forever. Thousands of rapid transitions with an active waiter must
        // always terminate.
        for _ in 0..4_000 {
            let gauge = PressureGauge::new();
            gauge.set(ResourcePressure::Critical);
            let waiter = {
                let gauge = gauge.clone();
                tokio::spawn(async move { gauge.wait_while_critical().await })
            };
            tokio::task::yield_now().await;
            gauge.set(ResourcePressure::Normal);
            tokio::time::timeout(std::time::Duration::from_secs(5), waiter)
                .await
                .expect("a waiter must never be stranded by a missed transition")
                .expect("the waiting task must not panic");
        }
    }
}
