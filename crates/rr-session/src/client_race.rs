//! Bounded pre-request client candidate ownership for multi-LINE establishment.
//!
//! One logical connection owns one engine, never reset or reused. Candidates may
//! race only through transport authentication: neither may send a VLESS request
//! or application data before adoption. This avoids duplicated destination side
//! effects and does not pretend that a VLESS response proves reachability.
//! The adapter owns I/O, elapsed time, health classification and cancellation;
//! this engine decides which results still belong to this establishment.

/// The only two candidate slots available to a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientCandidate {
    /// The initially preferred LINE.
    Primary,
    /// At most one alternate LINE, started by the adapter's explicit policy.
    Alternate,
}
impl ClientCandidate {
    const fn slot(self) -> usize {
        match self {
            Self::Primary => 0,
            Self::Alternate => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Unstarted,
    Pending,
    Failed,
    Retired,
}

/// Which pending operations the adapter must drop and reap.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientCancellations {
    primary: bool,
    alternate: bool,
}
impl ClientCancellations {
    /// Whether this candidate still had pending work at the terminal transition.
    pub const fn contains(self, candidate: ClientCandidate) -> bool {
        match candidate {
            ClientCandidate::Primary => self.primary,
            ClientCandidate::Alternate => self.alternate,
        }
    }
}

/// One-shot adoption authority. Deliberately neither Clone nor Copy.
///
/// The adapter drops the reported losing operation and consumes this value to
/// bind the selected authenticated transport before sending the VLESS request.
#[derive(Debug, Eq, PartialEq)]
pub struct ClientAdoption {
    candidate: ClientCandidate,
    cancel: ClientCancellations,
}
impl ClientAdoption {
    /// Pending loser operations to cancel; their later results are irrelevant.
    pub const fn cancellations(&self) -> ClientCancellations {
        self.cancel
    }
    /// Consumes the only adoption authority for this logical connection.
    pub const fn into_candidate(self) -> ClientCandidate {
        self.candidate
    }
}

/// Fixed-storage, exclusive-mutation establishment decisions.
///
/// `new` reserves the primary attempt. The adapter must supply only events for
/// this connection and serialize calls through its owning task. No time-based
/// lease is hidden here. An external deadline invokes `cancel`, and cancellation
/// is neutral health evidence. Neither failed nor cancelled slots can restart.
#[derive(Debug)]
pub struct ClientRace {
    states: [State; 2],
    terminal: bool,
}
impl ClientRace {
    /// Starts one establishment with a primary attempt reserved.
    pub const fn new() -> Self {
        Self {
            states: [State::Pending, State::Unstarted],
            terminal: false,
        }
    }

    /// Reserves the alternate once, on a hedge deadline or primary failure.
    /// Returns false after terminal state or if the slot was ever used.
    #[must_use]
    pub fn start_alternate(&mut self) -> bool {
        if self.terminal || self.states[1] != State::Unstarted {
            return false;
        }
        self.states[1] = State::Pending;
        true
    }

    /// Accepts a failed pending attempt. False means stale, duplicate, unstarted
    /// or terminal evidence, which must not update this establishment's health.
    /// The adapter separately decides whether an accepted error indicts a LINE.
    #[must_use]
    pub fn fail(&mut self, candidate: ClientCandidate) -> bool {
        if self.terminal || self.states[candidate.slot()] != State::Pending {
            return false;
        }
        self.states[candidate.slot()] = State::Failed;
        self.terminal = self.states == [State::Failed; 2];
        true
    }

    /// Adopts one successfully authenticated pending transport exactly once.
    ///
    /// Late success yields None: the adapter must dispose of that transport.
    /// The engine trusts the adapter's authentication verdict; this is not a
    /// cryptographic verifier. Established streams are never migrated or retried.
    #[must_use]
    pub fn adopt(&mut self, candidate: ClientCandidate) -> Option<ClientAdoption> {
        if self.terminal || self.states[candidate.slot()] != State::Pending {
            return None;
        }
        self.states[candidate.slot()] = State::Retired;
        let cancel = self.cancel();
        Some(ClientAdoption { candidate, cancel })
    }

    /// Terminates an establishment on cancellation/deadline/external rejection.
    /// Idempotent; subsequent calls return an empty cancellation set.
    #[must_use]
    pub fn cancel(&mut self) -> ClientCancellations {
        let cancel = ClientCancellations {
            primary: self.states[0] == State::Pending,
            alternate: self.states[1] == State::Pending,
        };
        self.states = [State::Retired; 2];
        self.terminal = true;
        cancel
    }

    /// Whether further starts and result events are permanently rejected.
    pub const fn is_terminal(&self) -> bool {
        self.terminal
    }
}
impl Default for ClientRace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ClientCandidate::{Alternate, Primary};

    #[test]
    fn single_line_adoption_does_not_start_an_alternate() {
        let mut race = ClientRace::new();
        assert_eq!(race.adopt(Alternate), None);
        let grant = race.adopt(Primary).unwrap();
        assert_eq!(grant.cancellations(), ClientCancellations::default());
        assert_eq!(grant.into_candidate(), Primary);
        assert!(race.is_terminal());
        assert!(!race.start_alternate());
    }
    #[test]
    fn winner_cancels_only_pending_loser_and_late_outcomes_are_ignored() {
        for winner in [Primary, Alternate] {
            let loser = if winner == Primary {
                Alternate
            } else {
                Primary
            };
            let mut race = ClientRace::new();
            assert!(race.start_alternate());
            assert!(!race.start_alternate());
            let grant = race.adopt(winner).unwrap();
            assert!(grant.cancellations().contains(loser));
            assert!(!grant.cancellations().contains(winner));
            assert_eq!(grant.into_candidate(), winner);
            assert_eq!(race.adopt(loser), None);
            assert!(!race.fail(loser));
            assert_eq!(race.cancel(), ClientCancellations::default());
        }
    }
    #[test]
    fn failed_primary_allows_one_fallback_without_restart() {
        let mut race = ClientRace::new();
        assert!(!race.fail(Alternate));
        assert!(race.fail(Primary));
        assert!(!race.fail(Primary));
        assert!(!race.is_terminal());
        assert!(race.start_alternate());
        assert_eq!(race.adopt(Primary), None);
        let grant = race.adopt(Alternate).unwrap();
        assert_eq!(grant.cancellations(), ClientCancellations::default());
    }
    #[test]
    fn both_failures_terminate_in_either_order() {
        for first in [Primary, Alternate] {
            let second = if first == Primary { Alternate } else { Primary };
            let mut race = ClientRace::new();
            assert!(race.start_alternate());
            assert!(race.fail(first));
            assert!(race.fail(second));
            assert!(race.is_terminal());
            assert!(!race.start_alternate());
            assert_eq!(race.adopt(first), None);
        }
    }
    #[test]
    fn deadline_and_user_cancel_are_absorbing_and_idempotent() {
        for alternate in [false, true] {
            let mut race = ClientRace::new();
            if alternate {
                assert!(race.start_alternate());
            }
            let cancel = race.cancel();
            assert!(cancel.contains(Primary));
            assert_eq!(cancel.contains(Alternate), alternate);
            assert_eq!(race.cancel(), ClientCancellations::default());
            assert!(!race.fail(Primary));
            assert_eq!(race.adopt(Primary), None);
        }
    }
    #[test]
    fn exhaustive_six_event_sequences_never_reopen_or_grant_twice() {
        for mut sequence in 0..6_u32.pow(6) {
            let mut race = ClientRace::new();
            let mut grants = 0;
            let mut starts = 0;
            let mut terminal_seen = false;
            for _ in 0..6 {
                match sequence % 6 {
                    0 => {
                        starts += u8::from(race.start_alternate());
                    }
                    1 => {
                        let accepted = race.fail(Primary);
                        assert!(!terminal_seen || !accepted);
                    }
                    2 => {
                        let accepted = race.fail(Alternate);
                        assert!(!terminal_seen || !accepted);
                    }
                    3 => {
                        grants += u8::from(race.adopt(Primary).is_some());
                    }
                    4 => {
                        grants += u8::from(race.adopt(Alternate).is_some());
                    }
                    _ => {
                        let _ = race.cancel();
                    }
                }
                assert!(grants <= 1 && starts <= 1);
                assert!(!terminal_seen || race.is_terminal());
                terminal_seen = race.is_terminal();
                sequence /= 6;
            }
        }
    }
}
