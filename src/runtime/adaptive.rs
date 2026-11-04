//! Adaptive soft-ceiling controller (design v1.6.0 §3.1–§3.4).
//!
//! # Design
//!
//! The controller runs only under `runtime.tuning.mode: "adaptive"`. Every
//! five seconds it samples the live utilization of each adjustable pool —
//! the six admission-governor ceilings and the direct-dial concurrency
//! ceiling, measured as held permits against the soft ceiling in effect —
//! and the process pressure state, then moves each knob inside hard bounds:
//!
//! - **Hard bounds**: a knob never exceeds its startup-derived value (the
//!   [`super::plan::PolicyResolution`] output the pool was constructed with;
//!   the ceiling semaphore's hard bound is the same number, so the limit
//!   holds even against a controller bug). The floor is the
//!   v1.5 built-in default for the field, lowered to the startup value when
//!   an operator pin sits below the default, so a pinned ceiling is
//!   respected exactly and the server always keeps a responsive minimum.
//! - **Hysteresis**: a knob scales up after [`SCALE_UP_TICKS`] consecutive
//!   ticks at or above the high watermark (85% utilization) and down after
//!   [`SCALE_DOWN_TICKS`] consecutive ticks at or below the low watermark
//!   (40%) — asymmetric: fast to protect, slow to relax. A tick between the
//!   watermarks resets both counters.
//! - **Dwell**: at least [`DWELL`] between successive changes to the same
//!   knob, so a knob moves at most once per six ticks.
//! - **Quantized steps**: each step is 25% of the startup value, rounded
//!   down to the knob's quantum (64 for counts, 16 for rates) with a minimum
//!   of one quantum, so small pools still move and large pools do not flap.
//! - **Critical pressure**: one tick at [`ResourcePressure::Critical`]
//!   clamps every knob to its floor in a single step, bypassing hysteresis
//!   and dwell — protection never waits. Recovery walks back up through the
//!   normal hysteresis.
//!
//! The direct-dial *rate* knob has no held-permit signal, so it consumes the
//! concurrency pool's utilization: dial demand is what saturates the rate
//! gate, and both knobs share one demand signal with independent bounds and
//! quanta.
//!
//! Everything the design forbids — timeouts, replay retention, buffer
//! sizes, pool hard sizes, the descriptor budget, listener topology — is
//! untouched: the controller writes only soft ceilings and the GCRA rate.
//!
//! State is bounded by construction: eight knobs, fixed counters, and one
//! retained transition record per knob. Transitions are observable through
//! one structured log event per knob change and, when `runtime.statusFile`
//! is set, an atomically rewritten JSON snapshot read by
//! `rust-reality runtime report`.

use std::{
    fmt,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use super::{AdmissionKind, DirectBarrier, PressureGauge, ResourceGovernor, ResourcePressure};
use crate::runtime::policy::{DirectBarrierPolicy, EffectivePolicy, ResourceGovernorPolicy};

/// How often the controller samples and decides. Decoupled from the 1 s
/// pressure monitor: the controller reacts to sustained conditions, not
/// transients.
pub const TICK_INTERVAL: Duration = Duration::from_secs(5);

/// Minimum time between successive changes to the same knob.
pub const DWELL: Duration = Duration::from_secs(30);

/// Ticks of dwell in units of [`TICK_INTERVAL`].
const DWELL_TICKS: u64 = DWELL.as_secs() / TICK_INTERVAL.as_secs();

/// Consecutive ticks at or above the high watermark before a scale-up.
pub const SCALE_UP_TICKS: u8 = 3;

/// Consecutive ticks at or below the low watermark before a scale-down.
pub const SCALE_DOWN_TICKS: u8 = 6;

/// Utilization at or above this percentage trips the scale-up counter.
pub const HIGH_UTILIZATION_PERCENT: u64 = 85;

/// Utilization at or below this percentage trips the scale-down counter.
pub const LOW_UTILIZATION_PERCENT: u64 = 40;

/// Step quantum for permit-count knobs (design §3.2).
const COUNT_QUANTUM: u64 = 64;

/// Step quantum for the dial-rate knob (design §3.2).
const RATE_QUANTUM: u64 = 16;

/// One adjustable soft ceiling, named by its configuration field path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Knob {
    /// `resourceGovernor.maxConnections`.
    Connections,
    /// `resourceGovernor.maxHandshakes`.
    Handshakes,
    /// `resourceGovernor.maxFallbacks`.
    Fallbacks,
    /// `resourceGovernor.maxCryptoOperations`.
    CryptoOperations,
    /// `resourceGovernor.maxReplayEntries`.
    ReplayEntries,
    /// `resourceGovernor.maxDnsLookups`.
    DnsLookups,
    /// `directBarrier.maxConcurrent`.
    DirectConcurrent,
    /// `directBarrier.maxPerSecond`.
    DirectPerSecond,
}

impl Knob {
    /// Every knob, in stable report order.
    const ALL: [Self; 8] = [
        Self::Connections,
        Self::Handshakes,
        Self::Fallbacks,
        Self::CryptoOperations,
        Self::ReplayEntries,
        Self::DnsLookups,
        Self::DirectConcurrent,
        Self::DirectPerSecond,
    ];

    /// Returns the stable configuration field path used in logs and reports.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Connections => "resourceGovernor.maxConnections",
            Self::Handshakes => "resourceGovernor.maxHandshakes",
            Self::Fallbacks => "resourceGovernor.maxFallbacks",
            Self::CryptoOperations => "resourceGovernor.maxCryptoOperations",
            Self::ReplayEntries => "resourceGovernor.maxReplayEntries",
            Self::DnsLookups => "resourceGovernor.maxDnsLookups",
            Self::DirectConcurrent => "directBarrier.maxConcurrent",
            Self::DirectPerSecond => "directBarrier.maxPerSecond",
        }
    }

    /// Returns the admission pool behind a governor knob.
    const fn admission_kind(self) -> Option<AdmissionKind> {
        match self {
            Self::Connections => Some(AdmissionKind::Connection),
            Self::Handshakes => Some(AdmissionKind::Handshake),
            Self::Fallbacks => Some(AdmissionKind::Fallback),
            Self::CryptoOperations => Some(AdmissionKind::CryptoOperation),
            Self::ReplayEntries => Some(AdmissionKind::ReplayEntry),
            Self::DnsLookups => Some(AdmissionKind::DnsLookup),
            Self::DirectConcurrent | Self::DirectPerSecond => None,
        }
    }

    /// Returns the step quantum: counts move in 64s, the dial rate in 16s.
    const fn quantum(self) -> u64 {
        match self {
            Self::DirectPerSecond => RATE_QUANTUM,
            _ => COUNT_QUANTUM,
        }
    }
}

/// Why a ceiling moved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeReason {
    /// Critical resource pressure clamped the knob to its floor in one step.
    CriticalPressure,
    /// Sustained utilization at or above the high watermark.
    HighUtilization,
    /// Sustained utilization at or below the low watermark.
    LowUtilization,
}

impl ChangeReason {
    /// Returns the stable identifier used in logs and reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CriticalPressure => "critical-pressure",
            Self::HighUtilization => "high-utilization",
            Self::LowUtilization => "low-utilization",
        }
    }
}

/// One applied transition, for the structured log event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeilingChange {
    /// The knob that moved.
    pub knob: Knob,
    /// Why it moved.
    pub reason: ChangeReason,
    /// Previous soft ceiling.
    pub from: u64,
    /// New soft ceiling.
    pub to: u64,
    /// The knob's documented minimum.
    pub floor: u64,
    /// The knob's startup-derived hard bound.
    pub ceiling: u64,
}

/// The persisted record of a knob's most recent transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeRecord {
    /// Controller tick at which the change was applied.
    pub tick: u64,
    /// Wall-clock time of the change, milliseconds since the Unix epoch.
    pub at_unix_ms: u64,
    /// Why the ceiling moved.
    pub reason: ChangeReason,
    /// Previous soft ceiling.
    pub from: u64,
    /// New soft ceiling.
    pub to: u64,
}

/// The result of one controller tick.
#[derive(Clone, Debug)]
pub struct TickOutcome {
    /// Every ceiling change applied this tick, in knob order.
    pub changes: Vec<CeilingChange>,
    /// The pressure state sampled this tick.
    pub pressure: ResourcePressure,
    /// Whether the pressure state changed since the previous tick.
    pub pressure_changed: bool,
}

/// The quantized step size: 25% of the startup value, rounded down to the
/// knob's quantum, with a minimum of one quantum so small pools still move.
fn quantized_step(startup_value: u64, quantum: u64) -> u64 {
    (startup_value / 4 / quantum * quantum).max(quantum)
}

/// Per-knob controller state. All arithmetic is saturating integer math:
/// the same inputs always produce the same transition.
struct KnobState {
    knob: Knob,
    /// Current soft ceiling, always within `[floor, hard]`.
    value: u64,
    /// Documented minimum that keeps the server responsive.
    floor: u64,
    /// Startup-derived value; the ceiling the controller may never exceed.
    hard: u64,
    /// Quantized ±25% step.
    step: u64,
    /// Consecutive ticks at or above the high watermark.
    above_ticks: u8,
    /// Consecutive ticks at or below the low watermark.
    below_ticks: u8,
    /// Tick of the last applied change, for the dwell gate.
    last_change_tick: Option<u64>,
    /// Ticks since the last applied change.
    ticks_in_state: u64,
    /// The most recent applied change.
    last_change: Option<ChangeRecord>,
}

impl KnobState {
    fn new(knob: Knob, startup_value: u64, floor: u64) -> Self {
        let floor = floor.min(startup_value).max(1);
        Self {
            knob,
            value: startup_value,
            floor,
            hard: startup_value,
            step: quantized_step(startup_value, knob.quantum()),
            above_ticks: 0,
            below_ticks: 0,
            last_change_tick: None,
            ticks_in_state: 0,
            last_change: None,
        }
    }

    fn dwell_elapsed(&self, tick: u64) -> bool {
        self.last_change_tick
            .is_none_or(|last| tick.saturating_sub(last) >= DWELL_TICKS)
    }

    fn record(&mut self, tick: u64, at_unix_ms: u64, reason: ChangeReason, to: u64) {
        let record = ChangeRecord {
            tick,
            at_unix_ms,
            reason,
            from: self.value,
            to,
        };
        self.value = to;
        self.above_ticks = 0;
        self.below_ticks = 0;
        self.ticks_in_state = 0;
        self.last_change_tick = Some(tick);
        self.last_change = Some(record);
    }

    /// Clamps the knob to its floor under critical pressure, bypassing
    /// hysteresis and dwell. Returns the change when the knob moved.
    fn clamp_to_floor(&mut self, tick: u64, at_unix_ms: u64) -> Option<CeilingChange> {
        self.above_ticks = 0;
        self.below_ticks = 0;
        if self.value == self.floor {
            return None;
        }
        let from = self.value;
        self.record(tick, at_unix_ms, ChangeReason::CriticalPressure, self.floor);
        Some(CeilingChange {
            knob: self.knob,
            reason: ChangeReason::CriticalPressure,
            from,
            to: self.floor,
            floor: self.floor,
            ceiling: self.hard,
        })
    }

    /// Advances the hysteresis FSM with one utilization sample. Returns the
    /// change when the knob moved.
    fn tick(&mut self, in_flight: u64, tick: u64, at_unix_ms: u64) -> Option<CeilingChange> {
        self.ticks_in_state = self.ticks_in_state.saturating_add(1);
        // Both sides are bounded by u32::MAX permits, so the scaled products
        // cannot overflow u64.
        if in_flight.saturating_mul(100) >= self.value.saturating_mul(HIGH_UTILIZATION_PERCENT) {
            self.above_ticks = self.above_ticks.saturating_add(1);
            self.below_ticks = 0;
        } else if in_flight.saturating_mul(100)
            <= self.value.saturating_mul(LOW_UTILIZATION_PERCENT)
        {
            self.below_ticks = self.below_ticks.saturating_add(1);
            self.above_ticks = 0;
        } else {
            self.above_ticks = 0;
            self.below_ticks = 0;
            return None;
        }
        let (reason, direction_up) = if self.above_ticks >= SCALE_UP_TICKS {
            (ChangeReason::HighUtilization, true)
        } else if self.below_ticks >= SCALE_DOWN_TICKS {
            (ChangeReason::LowUtilization, false)
        } else {
            return None;
        };
        if !self.dwell_elapsed(tick) {
            return None;
        }
        let target = if direction_up {
            self.value.saturating_add(self.step).min(self.hard)
        } else {
            self.value.saturating_sub(self.step).max(self.floor)
        };
        if target == self.value {
            // Already at the bound: reset the tripped counter so a knob
            // resting on its floor or hard bound never latches a pending move.
            self.above_ticks = 0;
            self.below_ticks = 0;
            return None;
        }
        let from = self.value;
        self.record(tick, at_unix_ms, reason, target);
        Some(CeilingChange {
            knob: self.knob,
            reason,
            from,
            to: target,
            floor: self.floor,
            ceiling: self.hard,
        })
    }
}

/// One knob in the published snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KnobStatus {
    /// Stable configuration field path.
    pub name: String,
    /// Soft ceiling currently in effect.
    pub value: u64,
    /// Documented minimum.
    pub floor: u64,
    /// Startup-derived hard bound.
    pub ceiling: u64,
    /// Permits held at snapshot time (for the rate knob, the concurrency
    /// pool's held permits — its demand signal).
    pub in_flight: u64,
    /// Ticks since the last change to this knob.
    pub ticks_in_state: u64,
    /// The most recent transition, when one has happened.
    pub last_change: Option<ChangeRecord>,
}

/// The controller snapshot published to the status file and the CLI.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdaptiveStatus {
    /// Snapshot schema version.
    pub schema_version: u32,
    /// Wall-clock time of the snapshot, milliseconds since the Unix epoch.
    pub updated_at_unix_ms: u64,
    /// Effective resource-pressure state at snapshot time.
    pub pressure: String,
    /// Every knob, in stable order.
    pub knobs: Vec<KnobStatus>,
}

impl fmt::Display for AdaptiveStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "pressure: {}", self.pressure)?;
        for knob in &self.knobs {
            writeln!(
                formatter,
                "{}: {} (floor {}, ceiling {}, in flight {}, ticks in state {})",
                knob.name,
                knob.value,
                knob.floor,
                knob.ceiling,
                knob.in_flight,
                knob.ticks_in_state
            )?;
            if let Some(change) = &knob.last_change {
                writeln!(
                    formatter,
                    "  last change: {} {} -> {} at unix ms {} (tick {})",
                    change.reason.as_str(),
                    change.from,
                    change.to,
                    change.at_unix_ms,
                    change.tick
                )?;
            }
        }
        Ok(())
    }
}

/// Failure to read a published adaptive status snapshot.
#[derive(Debug)]
pub enum StatusReadError {
    /// The file could not be read.
    Io {
        /// The configured status-file path.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },
    /// The file is not a valid adaptive status snapshot.
    Invalid {
        /// The configured status-file path.
        path: PathBuf,
        /// The underlying decoding error.
        source: serde_json::Error,
    },
}

impl fmt::Display for StatusReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "cannot read adaptive status file {}: {source}",
                    path.display()
                )
            }
            Self::Invalid { path, source } => write!(
                formatter,
                "adaptive status file {} is not a valid snapshot: {source}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StatusReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
        }
    }
}

/// Reads the last snapshot a running adaptive instance published.
///
/// # Errors
///
/// Returns [`StatusReadError`] when the file is unreadable or is not a valid
/// snapshot.
pub fn read_status(path: &Path) -> Result<AdaptiveStatus, StatusReadError> {
    let bytes = fs::read(path).map_err(|source| StatusReadError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| StatusReadError::Invalid {
        path: path.to_owned(),
        source,
    })
}

/// Writes a file atomically: a uniquely named temporary in the same
/// directory, flushed and synced, then renamed over the target. The pattern
/// matches the asset cache's atomic writes.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "status path has no parent"))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "status path has no file name")
        })?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let nonce = u64::from_ne_bytes(random);
    let temporary = parent.join(format!(
        ".{file_name}.{}-{nonce:016x}.tmp",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _unused = fs::remove_file(&temporary);
    }
    result
}

/// Returns the current wall clock in milliseconds since the Unix epoch,
/// saturating instead of failing on a broken clock.
#[must_use]
pub fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The adaptive controller: pure transition logic over the live admission
/// authorities, driven by the server loop one [`TICK_INTERVAL`] at a time.
///
/// Constructed only under `runtime.tuning.mode: "adaptive"`; under `fixed`
/// and `startup` no controller exists and every ceiling stays exactly where
/// startup put it.
pub struct AdaptiveController {
    knobs: Vec<KnobState>,
    governor: ResourceGovernor,
    direct_barrier: DirectBarrier,
    pressure: PressureGauge,
    status_file: Option<PathBuf>,
    tick_index: u64,
    last_pressure: ResourcePressure,
}

impl AdaptiveController {
    /// Builds the knob set from the effective startup policy.
    ///
    /// `policy` is the startup-resolved effective policy: each knob's hard
    /// bound is the value the pool was constructed with, and its floor is
    /// the v1.5 built-in default for the field (lowered to the startup value
    /// when an operator pin sits below the default).
    #[must_use]
    pub fn new(
        governor: ResourceGovernor,
        direct_barrier: DirectBarrier,
        pressure: PressureGauge,
        policy: &EffectivePolicy,
        status_file: Option<PathBuf>,
    ) -> Self {
        let defaults = ResourceGovernorPolicy::default();
        let barrier_defaults = DirectBarrierPolicy::default();
        let governor_policy = &policy.governor;
        let startup_values = [
            u64::from(governor_policy.max_connections),
            u64::from(governor_policy.max_handshakes),
            u64::from(governor_policy.max_fallbacks),
            u64::from(governor_policy.max_crypto_operations),
            u64::from(governor_policy.max_replay_entries),
            u64::from(governor_policy.max_dns_lookups),
            u64::from(policy.direct_barrier.max_concurrent),
            u64::from(policy.direct_barrier.max_per_second),
        ];
        let floors = [
            u64::from(defaults.max_connections),
            u64::from(defaults.max_handshakes),
            u64::from(defaults.max_fallbacks),
            u64::from(defaults.max_crypto_operations),
            u64::from(defaults.max_replay_entries),
            u64::from(defaults.max_dns_lookups),
            u64::from(barrier_defaults.max_concurrent),
            u64::from(barrier_defaults.max_per_second),
        ];
        let knobs = Knob::ALL
            .into_iter()
            .zip(startup_values)
            .zip(floors)
            .map(|((knob, startup), floor)| KnobState::new(knob, startup, floor))
            .collect();
        Self {
            knobs,
            governor,
            direct_barrier,
            pressure,
            status_file,
            tick_index: 0,
            last_pressure: ResourcePressure::Normal,
        }
    }

    /// Returns the configured status-file path, when one is set.
    #[must_use]
    pub fn status_file(&self) -> Option<&Path> {
        self.status_file.as_deref()
    }

    /// Returns the permits currently held against a knob's pool. The dial
    /// rate has no held-permit signal and consumes the concurrency pool's
    /// utilization, its demand signal.
    fn in_flight(&self, knob: Knob) -> u64 {
        if let Some(kind) = knob.admission_kind() {
            return self.governor.in_flight(kind);
        }
        self.direct_barrier.in_flight()
    }

    /// Runs one controller tick: sample, decide, apply, and report.
    ///
    /// `now_unix_ms` is caller-supplied wall clock for the transition
    /// records, so the decision logic itself is fully deterministic.
    pub fn tick(&mut self, now_unix_ms: u64) -> TickOutcome {
        self.tick_index = self.tick_index.saturating_add(1);
        let tick = self.tick_index;
        let pressure = self.pressure.state();
        let pressure_changed = pressure != self.last_pressure;
        self.last_pressure = pressure;

        let mut changes = Vec::new();
        if pressure == ResourcePressure::Critical {
            // Protection never waits: every knob drops to its floor in one
            // tick, bypassing hysteresis and dwell.
            for knob in &mut self.knobs {
                if let Some(change) = knob.clamp_to_floor(tick, now_unix_ms) {
                    changes.push(change);
                }
            }
        } else {
            let signals: Vec<u64> = self
                .knobs
                .iter()
                .map(|knob| self.in_flight(knob.knob))
                .collect();
            for (knob, in_flight) in self.knobs.iter_mut().zip(signals) {
                if let Some(change) = knob.tick(in_flight, tick, now_unix_ms) {
                    changes.push(change);
                }
            }
        }
        for change in &changes {
            self.apply(change);
        }
        TickOutcome {
            changes,
            pressure,
            pressure_changed,
        }
    }

    /// Applies one decided change to its pool or rate gate.
    fn apply(&self, change: &CeilingChange) {
        if let Some(kind) = change.knob.admission_kind() {
            self.governor.set_ceiling(kind, change.to);
        } else if change.knob == Knob::DirectConcurrent {
            self.direct_barrier.set_concurrency_ceiling(change.to);
        } else {
            self.direct_barrier
                .set_rate_per_second(u32::try_from(change.to).unwrap_or(u32::MAX));
        }
    }

    /// Builds the current snapshot with live held-permit counts.
    #[must_use]
    pub fn status(&self, now_unix_ms: u64) -> AdaptiveStatus {
        AdaptiveStatus {
            schema_version: 1,
            updated_at_unix_ms: now_unix_ms,
            pressure: self.pressure.state().as_str().to_owned(),
            knobs: self
                .knobs
                .iter()
                .map(|knob| KnobStatus {
                    name: knob.knob.name().to_owned(),
                    value: knob.value,
                    floor: knob.floor,
                    ceiling: knob.hard,
                    in_flight: self.in_flight(knob.knob),
                    ticks_in_state: knob.ticks_in_state,
                    last_change: knob.last_change,
                })
                .collect(),
        }
    }

    /// Atomically rewrites the status file. A no-op when
    /// `runtime.statusFile` is unset.
    ///
    /// # Errors
    ///
    /// Returns the I/O error when the file cannot be written.
    pub fn write_status(&self, now_unix_ms: u64) -> io::Result<()> {
        let Some(path) = &self.status_file else {
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(&self.status(now_unix_ms))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        write_atomic(path, &bytes)
    }
}

#[cfg(test)]
mod tests;
