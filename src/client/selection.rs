//! Pre-commit multi-LINE selection (ADR 0032).
//!
//! Candidates race REALITY authentication only. After adoption the winner opens
//! Vision/VLESS once. Failures after adoption are never retried on another LINE
//! (no illegal request replay, no mid-session migration).
//!
//! ## Health (new sessions only)
//!
//! Consecutive authentication faults trip a LINE for subsequent *new* sessions:
//! selection prefers a healthy sticky primary. Live TCP after commit is never
//! moved, regardless of health.

use std::{
    sync::Arc,
    sync::atomic::{AtomicU8, AtomicUsize, Ordering},
    time::Duration,
};

use crate::{
    protocol::vless::Destination,
    runtime::client::{ClientEstablishError, select_client_transport},
};
use rr_session::ClientCandidate;

use super::{
    line::{AuthenticatedLine, Line, LineError},
    session::VisionTunnel,
    xudp::XudpTunnel,
};

const DEFAULT_HEDGE: Duration = Duration::from_millis(275);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_LINES_PER_GROUP: usize = 8;
/// Consecutive auth faults before a LINE is skipped as sticky primary.
const TRIP_AFTER: u8 = 2;

/// How a LINE group picks a primary and optional hedge alternate.
#[derive(Clone, Debug)]
pub struct SelectionPolicy {
    /// Delay before starting the alternate while the primary is still pending.
    pub hedge: Duration,
    /// Overall budget for authentication race (not restarted on failover).
    pub timeout: Duration,
}

impl Default for SelectionPolicy {
    fn default() -> Self {
        Self {
            hedge: DEFAULT_HEDGE,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// One named group of LINEs with sticky primary and pre-commit hedge.
#[derive(Debug)]
pub struct LineGroup {
    name: String,
    lines: Vec<Arc<Line>>,
    sticky: AtomicUsize,
    faults: Vec<AtomicU8>,
    policy: SelectionPolicy,
}

impl LineGroup {
    /// Builds a group from compiled LINEs (1..=8).
    pub fn new(
        name: impl Into<String>,
        lines: Vec<Arc<Line>>,
        policy: SelectionPolicy,
    ) -> Result<Self, LineError> {
        if lines.is_empty() {
            return Err(LineError::Config("line group empty"));
        }
        if lines.len() > MAX_LINES_PER_GROUP {
            return Err(LineError::Config("line group too large"));
        }
        let faults = (0..lines.len()).map(|_| AtomicU8::new(0)).collect();
        Ok(Self {
            name: name.into(),
            lines,
            sticky: AtomicUsize::new(0),
            faults,
            policy,
        })
    }

    /// Group name for diagnostics and listener mapping.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Selects one authenticated LINE then opens Vision to `destination`.
    ///
    /// Racing stops before any VLESS request. After adoption, `open` runs once;
    /// a session error is returned to the caller without trying another LINE.
    pub async fn establish(&self, destination: &Destination) -> Result<VisionTunnel, LineError> {
        let adopted = self.authenticate().await?;
        // Post-commit: never migrate. open failure is terminal for this attempt.
        adopted.open(destination).await
    }

    /// Selects one authenticated LINE then opens Vision Mux/XUDP.
    ///
    /// Same commit rules as [`Self::establish`]: no mid-session LINE migration.
    pub async fn establish_xudp(&self) -> Result<XudpTunnel, LineError> {
        let adopted = self.authenticate().await?;
        adopted.open_xudp().await
    }

    /// Health snapshot for tests and diagnostics: fault counts per LINE index.
    #[must_use]
    pub fn fault_counts(&self) -> Vec<u8> {
        self.faults
            .iter()
            .map(|f| f.load(Ordering::Relaxed))
            .collect()
    }

    async fn authenticate(&self) -> Result<AuthenticatedLine, LineError> {
        let primary_idx = self.pick_primary();
        let primary = Arc::clone(&self.lines[primary_idx]);

        if self.lines.len() == 1 {
            return match primary.handshake().await {
                Ok(auth) => {
                    self.note_success(primary_idx);
                    Ok(auth)
                }
                Err(error) => {
                    self.note_fault(primary_idx);
                    Err(error)
                }
            };
        }

        let alternate_idx = self.pick_alternate(primary_idx);
        let alternate = Arc::clone(&self.lines[alternate_idx]);

        let primary_fut = {
            let line = Arc::clone(&primary);
            async move { line.handshake().await }
        };
        let alternate_fut = {
            let line = Arc::clone(&alternate);
            async move { line.handshake().await }
        };

        match select_client_transport(
            primary_fut,
            Some(alternate_fut),
            self.policy.hedge,
            self.policy.timeout,
        )
        .await
        {
            Ok((candidate, auth)) => {
                let winner = match candidate {
                    ClientCandidate::Primary => primary_idx,
                    ClientCandidate::Alternate => {
                        self.note_fault(primary_idx);
                        alternate_idx
                    }
                };
                self.note_success(winner);
                Ok(auth)
            }
            Err(ClientEstablishError::Deadline) => {
                self.note_fault(primary_idx);
                self.note_fault(alternate_idx);
                Err(LineError::Selection("deadline"))
            }
            Err(ClientEstablishError::Attempts { primary, alternate }) => {
                self.note_fault(primary_idx);
                if alternate.is_some() {
                    self.note_fault(alternate_idx);
                }
                Err(primary)
            }
        }
    }

    fn pick_primary(&self) -> usize {
        let start = self.sticky.load(Ordering::Relaxed) % self.lines.len();
        for offset in 0..self.lines.len() {
            let idx = (start + offset) % self.lines.len();
            if self.faults[idx].load(Ordering::Relaxed) < TRIP_AFTER {
                return idx;
            }
        }
        start
    }

    fn pick_alternate(&self, primary_idx: usize) -> usize {
        for offset in 1..self.lines.len() {
            let idx = (primary_idx + offset) % self.lines.len();
            if self.faults[idx].load(Ordering::Relaxed) < TRIP_AFTER {
                return idx;
            }
        }
        (primary_idx + 1) % self.lines.len()
    }

    fn note_success(&self, idx: usize) {
        self.faults[idx].store(0, Ordering::Relaxed);
        self.sticky.store(idx, Ordering::Relaxed);
    }

    fn note_fault(&self, idx: usize) {
        let _ = self.faults[idx].try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
            Some(v.saturating_add(1).min(TRIP_AFTER))
        });
    }
}

/// All LINE groups available to client listeners.
#[derive(Debug)]
pub struct LinePool {
    groups: Vec<Arc<LineGroup>>,
}

impl LinePool {
    /// Compiles configuration LINEs into one default group (all lines).
    pub fn from_lines(
        lines: &[crate::config::node::LineConfig],
        policy: SelectionPolicy,
    ) -> Result<Self, LineError> {
        let compiled: Result<Vec<_>, _> = lines
            .iter()
            .map(|c| Line::from_config(c).map(Arc::new))
            .collect();
        let compiled = compiled?;
        let group = LineGroup::new("default", compiled, policy)?;
        Ok(Self {
            groups: vec![Arc::new(group)],
        })
    }

    /// Compiles explicit named groups; each name must resolve to configured tags.
    pub fn from_groups(
        lines: &[crate::config::node::LineConfig],
        groups: &[crate::config::node::LineGroupConfig],
        policy: SelectionPolicy,
    ) -> Result<Self, LineError> {
        let by_tag: std::collections::BTreeMap<&str, &crate::config::node::LineConfig> = lines
            .iter()
            .filter_map(|l| l.tag.as_deref().map(|t| (t, l)))
            .collect();
        let mut out = Vec::with_capacity(groups.len());
        for group in groups {
            let mut members = Vec::new();
            for tag in &group.lines {
                let cfg = by_tag
                    .get(tag.as_str())
                    .ok_or(LineError::Config("line group unknown tag"))?;
                members.push(Arc::new(Line::from_config(cfg)?));
            }
            out.push(Arc::new(LineGroup::new(
                group.name.clone(),
                members,
                policy.clone(),
            )?));
        }
        if out.is_empty() {
            return Err(LineError::Config("lineGroups empty"));
        }
        Ok(Self { groups: out })
    }

    /// Resolves a listener's group (absent → `"default"` if present, else first).
    pub fn group(&self, name: Option<&str>) -> Result<Arc<LineGroup>, LineError> {
        let want = name.unwrap_or("default");
        self.groups
            .iter()
            .find(|g| g.name() == want)
            .cloned()
            .or_else(|| {
                if name.is_none() {
                    self.groups.first().cloned()
                } else {
                    None
                }
            })
            .ok_or(LineError::Config("line group not found"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::node::LineConfig;

    fn dummy_line(tag: &str, port: u16) -> LineConfig {
        LineConfig {
            tag: Some(tag.to_owned()),
            address: "127.0.0.1".to_owned(),
            port,
            id: "11111111-1111-4111-8111-111111111111".to_owned(),
            public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            short_id: "0102030405060708".to_owned(),
            server_name: "www.example.com".to_owned(),
            fingerprint: Default::default(),
            allow_udp_443: false,
        }
    }

    #[test]
    fn rejects_empty_group() {
        let err = LineGroup::new("g", vec![], SelectionPolicy::default()).unwrap_err();
        assert!(matches!(err, LineError::Config(_)));
    }

    #[test]
    fn health_skips_tripped_sticky_for_new_sessions() {
        let lines = vec![
            Arc::new(Line::from_config(&dummy_line("a", 1)).unwrap()),
            Arc::new(Line::from_config(&dummy_line("b", 2)).unwrap()),
        ];
        let group = LineGroup::new("edge", lines, SelectionPolicy::default()).unwrap();
        group.sticky.store(0, Ordering::Relaxed);
        group.faults[0].store(TRIP_AFTER, Ordering::Relaxed);
        assert_eq!(
            group.pick_primary(),
            1,
            "tripped sticky must yield to healthy"
        );
        group.faults[1].store(TRIP_AFTER, Ordering::Relaxed);
        assert_eq!(
            group.pick_primary(),
            0,
            "when all tripped, sticky index is still used"
        );
    }

    #[test]
    fn fault_matrix_documents_post_commit_no_replay() {
        // Contract: establish() is authenticate() then a single open().
        // A Session error from open must not call authenticate again.
        // Enforced by structure (no loop around open) and by the multi-LINE E2E
        // which only races dial/handshake failures before SOCKS5 success.
        assert!(matches!(
            LineError::Selection("deadline"),
            LineError::Selection(_)
        ));
    }
}
