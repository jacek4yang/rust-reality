//! Datagram packetization-layer path MTU discovery (RFC 8899 style).
//!
//! Sizes are channel packet sizes: the UDP payload of one native channel
//! datagram. Each sending direction of each session runs one
//! [`PmtuProber`]. The prober starts at [`BASE_PLPMTU`], which every
//! IPv4/IPv6 path carrying QUIC already supports, and binary-searches upward
//! with padded, authenticated PROBE packets; only an acknowledged probe raises
//! the packetization limit. Ordinary data loss never changes the limit.
//!
//! Back-off has two inputs. Kernel feedback: sockets set DF
//! (`IP_PMTUDISC_DO`), so an ICMP Packet Too Big / Fragmentation Needed
//! lowers the kernel route MTU and the next oversized send fails with
//! `EMSGSIZE`; the caller reports that through [`PmtuProber::on_send_too_big`]
//! with the kernel's current path MTU. Black holes (ICMP filtered): a
//! confirmation probe at the current size runs periodically, and when every
//! retry of it is lost the limit falls back to the base (or to
//! [`MIN_PLPMTU`] when the base itself failed) and the search restarts.
//! A raise timer periodically re-searches upward so a path whose MTU grew
//! mid-session is used again.
//!
//! The state machine is pure: time enters as an explicit input and the
//! caller sends the probes it returns.

use std::time::{Duration, Instant};

/// Floor after kernel feedback or a base black hole (IPv4 576 minus headers,
/// rounded down).
pub const MIN_PLPMTU: usize = 512;

/// Starting packetization limit; QUIC's minimum datagram size.
pub const BASE_PLPMTU: usize = 1200;

/// Largest channel packet ever probed (9000-byte jumbo frames, IPv4).
pub const MAX_PLPMTU: usize = 9000 - 28;

/// Converts an IP-layer MTU into a channel packet size for one family.
#[must_use]
pub const fn plpmtu_from_ip_mtu(ip_mtu: usize, ipv6: bool) -> usize {
    let overhead = if ipv6 { 40 + 8 } else { 20 + 8 };
    let size = ip_mtu.saturating_sub(overhead);
    if size < MIN_PLPMTU {
        MIN_PLPMTU
    } else if size > MAX_PLPMTU {
        MAX_PLPMTU
    } else {
        size
    }
}

/// Discovery timers and search parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtuTimers {
    /// Wait for one probe acknowledgement.
    pub probe_timeout: Duration,
    /// Transmissions of one probe size before it is declared lost.
    pub max_probes: u32,
    /// Interval of confirmation probes at the current size (black-hole
    /// detection).
    pub confirm_interval: Duration,
    /// Interval after which a completed search probes upward again.
    pub raise_interval: Duration,
    /// Search stops when the unexplored range is narrower than this.
    pub granularity: usize,
}

impl Default for PmtuTimers {
    fn default() -> Self {
        Self {
            probe_timeout: Duration::from_secs(1),
            max_probes: 3,
            confirm_interval: Duration::from_secs(15),
            raise_interval: Duration::from_secs(600),
            granularity: 16,
        }
    }
}

/// One probe the caller must send: a PROBE packet of exactly `size` bytes
/// carrying `id`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PmtuProbe {
    /// Probe identifier echoed by the PROBE_ACK.
    pub id: u32,
    /// Exact channel packet size.
    pub size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Purpose {
    Search,
    Confirm,
}

#[derive(Clone, Copy, Debug)]
struct Outstanding {
    id: u32,
    size: usize,
    sent: Instant,
    attempts: u32,
    purpose: Purpose,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Fixed,
    Search { high: usize },
    Complete { next_raise: Instant },
}

/// Per-direction path MTU state.
#[derive(Clone, Debug)]
pub struct PmtuProber {
    timers: PmtuTimers,
    current: usize,
    ceiling: usize,
    max_ceiling: usize,
    phase: Phase,
    outstanding: Option<Outstanding>,
    next_id: u32,
    next_confirm: Instant,
    black_holes: u64,
}

impl PmtuProber {
    /// Discovery from [`BASE_PLPMTU`] up to `ceiling` (the local interface or
    /// kernel route limit).
    #[must_use]
    pub fn discover(ceiling: usize, timers: PmtuTimers, now: Instant) -> Self {
        let ceiling = ceiling.clamp(MIN_PLPMTU, MAX_PLPMTU);
        let current = BASE_PLPMTU.min(ceiling);
        Self {
            timers,
            current,
            ceiling,
            max_ceiling: ceiling,
            phase: Phase::Search { high: ceiling },
            outstanding: None,
            next_id: 1,
            next_confirm: now + timers.confirm_interval,
            black_holes: 0,
        }
    }

    /// A fixed operator-configured limit; never probes.
    #[must_use]
    pub fn fixed(size: usize, now: Instant) -> Self {
        let size = size.clamp(MIN_PLPMTU, MAX_PLPMTU);
        Self {
            timers: PmtuTimers::default(),
            current: size,
            ceiling: size,
            max_ceiling: size,
            phase: Phase::Fixed,
            outstanding: None,
            next_id: 1,
            next_confirm: now,
            black_holes: 0,
        }
    }

    /// Current packetization limit: no channel packet may exceed it.
    #[must_use]
    pub const fn plpmtu(&self) -> usize {
        self.current
    }

    /// Whether the upward search has converged (or the limit is fixed).
    #[must_use]
    pub const fn search_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete { .. } | Phase::Fixed)
    }

    /// Black holes detected so far.
    #[must_use]
    pub const fn black_holes(&self) -> u64 {
        self.black_holes
    }

    fn take_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn launch(&mut self, size: usize, purpose: Purpose, now: Instant) -> PmtuProbe {
        let id = self.take_id();
        self.outstanding = Some(Outstanding {
            id,
            size,
            sent: now,
            attempts: 1,
            purpose,
        });
        PmtuProbe { id, size }
    }

    fn probe_lost(&mut self, lost: Outstanding, now: Instant) {
        match lost.purpose {
            Purpose::Search => {
                if let Phase::Search { high } = &mut self.phase {
                    *high = (*high).min(lost.size.saturating_sub(1));
                }
            }
            Purpose::Confirm => {
                // Black hole: the validated size stopped working without any
                // kernel feedback. Fall back and search again below it.
                self.black_holes += 1;
                let failed = self.current;
                self.current = if failed > BASE_PLPMTU {
                    BASE_PLPMTU
                } else {
                    MIN_PLPMTU
                };
                self.phase = Phase::Search {
                    high: failed.saturating_sub(1).max(self.current),
                };
                self.next_confirm = now + self.timers.confirm_interval;
            }
        }
    }

    /// Advances timers and returns the probe to send now, if any.
    pub fn poll(&mut self, now: Instant) -> Option<PmtuProbe> {
        if self.phase == Phase::Fixed {
            return None;
        }
        if let Some(mut outstanding) = self.outstanding {
            if now.saturating_duration_since(outstanding.sent) < self.timers.probe_timeout {
                return None;
            }
            if outstanding.attempts < self.timers.max_probes {
                outstanding.attempts += 1;
                outstanding.sent = now;
                self.outstanding = Some(outstanding);
                return Some(PmtuProbe {
                    id: outstanding.id,
                    size: outstanding.size,
                });
            }
            self.outstanding = None;
            self.probe_lost(outstanding, now);
        }
        match self.phase {
            Phase::Fixed => None,
            Phase::Search { high } => {
                let low = self.current;
                if high <= low || high - low < self.timers.granularity {
                    self.phase = Phase::Complete {
                        next_raise: now + self.timers.raise_interval,
                    };
                    self.next_confirm = now + self.timers.confirm_interval;
                    return None;
                }
                let size = low + (high - low).div_ceil(2);
                Some(self.launch(size, Purpose::Search, now))
            }
            Phase::Complete { next_raise } => {
                if now >= next_raise {
                    // Kernel feedback ages out; a raise reconsiders the
                    // original interface bound.
                    self.ceiling = self.max_ceiling;
                    if self.ceiling.saturating_sub(self.current) >= self.timers.granularity {
                        self.phase = Phase::Search { high: self.ceiling };
                        let size = self.current + (self.ceiling - self.current).div_ceil(2);
                        return Some(self.launch(size, Purpose::Search, now));
                    }
                    self.phase = Phase::Complete {
                        next_raise: now + self.timers.raise_interval,
                    };
                }
                if now >= self.next_confirm {
                    self.next_confirm = now + self.timers.confirm_interval;
                    return Some(self.launch(self.current, Purpose::Confirm, now));
                }
                None
            }
        }
    }

    /// Earliest instant at which [`Self::poll`] may have work.
    #[must_use]
    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if let Some(outstanding) = self.outstanding {
            return Some(outstanding.sent + self.timers.probe_timeout);
        }
        match self.phase {
            Phase::Fixed => None,
            Phase::Search { .. } => Some(now),
            Phase::Complete { next_raise } => Some(next_raise.min(self.next_confirm)),
        }
    }

    /// Applies one authenticated PROBE_ACK.
    pub fn on_probe_ack(&mut self, id: u32, size: usize, now: Instant) {
        let Some(outstanding) = self.outstanding else {
            return;
        };
        if outstanding.id != id || outstanding.size != size {
            return;
        }
        self.outstanding = None;
        match outstanding.purpose {
            Purpose::Search => {
                if size > self.current && size <= self.ceiling {
                    self.current = size;
                }
            }
            Purpose::Confirm => {
                self.next_confirm = now + self.timers.confirm_interval;
            }
        }
    }

    /// Applies kernel feedback: a send of `attempted` bytes failed with
    /// `EMSGSIZE`. `kernel_limit` is the kernel's current path MTU converted
    /// to a channel packet size, when the socket can report it.
    pub fn on_send_too_big(&mut self, attempted: usize, kernel_limit: Option<usize>) {
        let limit = kernel_limit
            .unwrap_or(attempted.saturating_sub(1))
            .min(attempted.saturating_sub(1))
            .clamp(MIN_PLPMTU, MAX_PLPMTU);
        self.ceiling = self.ceiling.min(limit).max(MIN_PLPMTU);
        if self.current > self.ceiling {
            self.current = self.ceiling;
        }
        if let Phase::Search { high } = &mut self.phase {
            *high = (*high).min(self.ceiling);
        }
        if self
            .outstanding
            .is_some_and(|outstanding| outstanding.size > self.ceiling)
        {
            self.outstanding = None;
        }
    }

    /// The upper bound discovery may probe.
    #[must_use]
    pub const fn ceiling(&self) -> usize {
        self.ceiling
    }
}
