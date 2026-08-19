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
use crate::config::{DirectBarrierConfig, PolicyConfig, ResourceGovernorConfig};

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
        policy: &PolicyConfig,
        status_file: Option<PathBuf>,
    ) -> Self {
        let defaults = ResourceGovernorConfig::default();
        let barrier_defaults = DirectBarrierConfig::default();
        let governor_policy = &policy.resource_governor;
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
mod tests {
    use super::{AdaptiveController, ChangeReason, PolicyConfig, quantized_step, read_status};
    use crate::config::{DirectBarrierConfig, ResourceGovernorConfig};
    use crate::runtime::{
        AdmissionKind, DirectBarrier, PressureGauge, ResourceGovernor, ResourcePressure,
    };

    /// A policy whose startup values sit above the v1.5 defaults, so every
    /// knob has room to move in both directions.
    fn test_policy() -> PolicyConfig {
        PolicyConfig {
            resource_governor: ResourceGovernorConfig {
                max_connections: 32_768,
                max_handshakes: 4_096,
                max_fallbacks: 2_048,
                max_crypto_operations: 512,
                max_replay_entries: 131_072,
                max_dns_lookups: 256,
                ..ResourceGovernorConfig::default()
            },
            direct_barrier: DirectBarrierConfig {
                max_concurrent: 8_192,
                max_per_second: 16_384,
            },
            ..PolicyConfig::default()
        }
    }

    fn test_controller() -> AdaptiveController {
        let policy = test_policy();
        AdaptiveController::new(
            ResourceGovernor::new(&policy.resource_governor),
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
            ResourceGovernor::new(&policy.resource_governor),
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
        policy.resource_governor.max_dns_lookups = 32;
        let controller = AdaptiveController::new(
            ResourceGovernor::new(&policy.resource_governor),
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
}
