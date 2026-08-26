//! Runtime-independent rendezvous policy for the bilateral raw-relay boundary.
//!
//! When a Vision direction reaches its raw boundary it must choose between the
//! bilateral pair relay and an independent directional relay. That choice is
//! better if the peer has had a chance to publish its own boundary state first:
//! a peer whose boundary flight is already queued only needs to be *scheduled*
//! to become pairable.
//!
//! The policy is deliberately not a wait. It never sleeps, never arms a timer,
//! and never blocks on the peer, because a direction must not depend on its peer
//! for liveness. It only spends a small, fixed number of cooperative scheduling
//! points before committing.
//!
//! Deciding *whether to spend another scheduling point* is pure: it depends on
//! the observed peer state and on how much of the budget is left. Only the
//! scheduling point itself belongs to the runtime adapter, which is what keeps
//! this policy testable and fuzzable without a runtime.

/// What the runtime adapter should do next while approaching the raw boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RendezvousStep {
    /// Spend one cooperative scheduling point, then observe the peer again.
    ///
    /// The adapter yields to its executor. It must not sleep, arm a timer, or
    /// wait on the peer.
    Yield,
    /// Stop observing and commit the raw-relay form now.
    ///
    /// Either the peer is already pairable, or the bounded budget is spent.
    Commit,
}

/// A bounded, sleep-free budget of scheduling points before committing.
///
/// The budget is small and fixed. Exhausting it is a normal outcome, not an
/// error: an unpaired direction simply commits to an independent relay, which is
/// why no direction can be starved by a peer that never arrives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PairRendezvous {
    yields_remaining: u8,
    committed: bool,
}

impl PairRendezvous {
    /// Cooperative scheduling points one direction may spend on the peer.
    ///
    /// Two is enough for a peer whose boundary flight is already queued to be
    /// polled and publish its state, and small enough that an absent peer costs
    /// a bounded, constant amount of work rather than a latency penalty.
    pub const YIELD_BUDGET: u8 = 2;

    /// Starts a fresh rendezvous with the full budget.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            yields_remaining: Self::YIELD_BUDGET,
            committed: false,
        }
    }

    /// Decides the next step from the freshly observed peer state.
    ///
    /// `peer_can_pair` is the adapter's observation of shared state; this
    /// function performs no observation of its own. Once it returns
    /// [`RendezvousStep::Commit`] it keeps returning `Commit`, so the loop it
    /// drives always terminates.
    pub const fn step(&mut self, peer_can_pair: bool) -> RendezvousStep {
        if self.committed || peer_can_pair || self.yields_remaining == 0 {
            self.committed = true;
            return RendezvousStep::Commit;
        }
        self.yields_remaining -= 1;
        RendezvousStep::Yield
    }

    /// Whether the rendezvous already decided to commit.
    #[must_use]
    pub const fn committed(&self) -> bool {
        self.committed
    }

    /// Scheduling points still available.
    #[must_use]
    pub const fn yields_remaining(&self) -> u8 {
        self.yields_remaining
    }

    /// Scheduling points already spent, never above [`Self::YIELD_BUDGET`].
    #[must_use]
    pub const fn yields_spent(&self) -> u8 {
        Self::YIELD_BUDGET - self.yields_remaining
    }
}

impl Default for PairRendezvous {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{PairRendezvous, RendezvousStep};

    /// Drives a rendezvous the way the adapter does and returns the yield count.
    fn drive(peer_pairable_at: Option<u8>) -> (u8, RendezvousStep) {
        let mut rendezvous = PairRendezvous::new();
        let mut observations = 0_u8;
        loop {
            let pairable = peer_pairable_at.is_some_and(|at| observations >= at);
            observations += 1;
            match rendezvous.step(pairable) {
                RendezvousStep::Yield => {
                    assert!(
                        rendezvous.yields_spent() <= PairRendezvous::YIELD_BUDGET,
                        "spent more scheduling points than the budget allows"
                    );
                }
                step @ RendezvousStep::Commit => return (rendezvous.yields_spent(), step),
            }
        }
    }

    #[test]
    fn an_already_pairable_peer_costs_no_scheduling_point() {
        assert_eq!(drive(Some(0)), (0, RendezvousStep::Commit));
    }

    #[test]
    fn an_absent_peer_commits_after_exactly_the_budget() {
        assert_eq!(
            drive(None),
            (PairRendezvous::YIELD_BUDGET, RendezvousStep::Commit)
        );
    }

    #[test]
    fn a_peer_that_arrives_mid_rendezvous_stops_the_budget_early() {
        for arrival in 1..=PairRendezvous::YIELD_BUDGET {
            let (spent, step) = drive(Some(arrival));
            assert_eq!(step, RendezvousStep::Commit);
            assert_eq!(
                spent, arrival,
                "a peer arriving after {arrival} scheduling points cost {spent}"
            );
        }
    }

    #[test]
    fn commit_is_absorbing() {
        // The loop the adapter writes must terminate even if it keeps asking,
        // and a peer that becomes unpairable again cannot reopen the rendezvous.
        let mut rendezvous = PairRendezvous::new();
        while rendezvous.step(false) == RendezvousStep::Yield {}
        assert!(rendezvous.committed());
        for _ in 0..16 {
            assert_eq!(rendezvous.step(false), RendezvousStep::Commit);
            assert_eq!(rendezvous.yields_remaining(), 0);
        }

        let mut early = PairRendezvous::new();
        assert_eq!(early.step(true), RendezvousStep::Commit);
        assert_eq!(early.yields_spent(), 0, "an early commit spends nothing");
        assert_eq!(
            early.step(false),
            RendezvousStep::Commit,
            "a committed rendezvous must not reopen"
        );
    }

    #[test]
    fn the_budget_is_never_exceeded_for_any_peer_arrival() {
        // Exhaustive over every arrival time, including never arriving.
        let mut arrivals: [Option<u8>; 5] = [None; 5];
        for (index, slot) in arrivals.iter_mut().enumerate().skip(1) {
            *slot = Some(u8::try_from(index - 1).expect("small index"));
        }
        for arrival in arrivals {
            let (spent, step) = drive(arrival);
            assert_eq!(step, RendezvousStep::Commit);
            assert!(
                spent <= PairRendezvous::YIELD_BUDGET,
                "arrival {arrival:?} spent {spent} scheduling points"
            );
        }
    }

    #[test]
    fn the_budget_matches_the_documented_two_scheduling_points() {
        assert_eq!(PairRendezvous::YIELD_BUDGET, 2);
        assert_eq!(PairRendezvous::new().yields_remaining(), 2);
        assert_eq!(PairRendezvous::new().yields_spent(), 0);
    }

    #[test]
    fn rendezvous_values_remain_compact() {
        assert_eq!(core::mem::size_of::<PairRendezvous>(), 2);
        assert_eq!(core::mem::size_of::<RendezvousStep>(), 1);
    }
}
