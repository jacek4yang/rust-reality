//! Offline `runtime explain` report: the detected machine, the resolved
//! profile, the bootstrap runtime topology, and the effective numeric policy
//! with per-field provenance.
//!
//! The report is computed exactly like a serve startup would — one
//! [`MachineReport`] detection, the same profile resolution, the same
//! [`StartupPlan`](crate::runtime::plan::StartupPlan) derivation — but it
//! never binds a listener, spawns a runtime, or touches any live server.
//! Kernel-level tuning suggestions are advisory text only: the process never
//! writes sysctls, other processes' rlimits, or cgroup files.

use std::fmt;

use serde::Serialize;

use crate::{
    config::Config,
    runtime::{
        machine::MachineReport,
        plan::{RuntimeTopology, resolve_policy},
    },
};

/// The schema version of the JSON report. Bump on any shape change.
pub const EXPLAIN_SCHEMA_VERSION: u32 = 1;

/// One complete `runtime explain` report.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainReport {
    /// The report schema version.
    pub schema_version: u32,
    /// The detected machine view the derivation budgeted against.
    pub machine: ExplainMachine,
    /// The configured `runtime.profile`.
    pub profile: &'static str,
    /// The resource mode the profile resolves to on this machine.
    pub resolved_resource_mode: &'static str,
    /// The effective `runtime.tuning.mode`.
    pub tuning_mode: &'static str,
    /// The configured `runtime.tuning.objective`.
    pub objective: &'static str,
    /// The Tokio runtime topology the bootstrap selected.
    pub bootstrap: ExplainBootstrap,
    /// The effective value, source, and bounds of every policy field.
    pub fields: Vec<ExplainField>,
    /// Kernel-level tuning suggestions; advisory only, never applied.
    pub advisories: Vec<String>,
}

/// The machine view reported by `runtime explain`.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainMachine {
    /// Logical CPUs visible through process affinity.
    pub logical_cpus: usize,
    /// CPU count after applying a finite cgroup quota.
    pub effective_cpus: usize,
    /// Inherited soft descriptor limit.
    pub fd_soft_limit: u64,
    /// Inherited hard descriptor limit.
    pub fd_hard_limit: u64,
    /// Where the memory quantities come from.
    pub memory_source: &'static str,
    /// Effective memory ceiling, or zero when unavailable.
    pub memory_total_bytes: u64,
    /// Current cgroup memory usage when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_current_bytes: Option<u64>,
    /// Finite cgroup CPU quota when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota_microseconds: Option<u64>,
    /// Cgroup CPU quota period when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period_microseconds: Option<u64>,
    /// Whether the cgroup v2 single-tenancy boundary is fully observable.
    pub tenancy_boundary_observable: bool,
}

/// The bootstrap-selected Tokio pool sizes.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainBootstrap {
    /// The effective worker-thread count.
    pub worker_threads: usize,
    /// The effective blocking-pool size.
    pub max_blocking_threads: usize,
    /// `dedicated` when the pools were sized from the machine, or
    /// `tokio-default` when the shared/standard posture kept the defaults.
    pub sizing: &'static str,
}

/// One effective policy value with its provenance and bounds.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainField {
    /// Stable dotted field path, e.g. `resourceGovernor.maxConnections`.
    pub field: &'static str,
    /// The effective value (booleans report 0/1).
    pub value: u64,
    /// `derived`, `override` (operator-pinned), or `default`.
    pub source: &'static str,
    /// The objective multiplier applied, for derived scalable fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multiplier: Option<f64>,
    /// The safety floor the derivation applies last, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub floor: Option<u64>,
    /// The hard cap the derivation never exceeds, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap: Option<u64>,
}

/// Builds the offline explanation for one loaded configuration.
///
/// Everything is read from the supplied machine report; the caller detects
/// once so the serve bootstrap and this report share the detection cost.
#[must_use]
pub fn explain_config(config: &Config, machine: &MachineReport) -> ExplainReport {
    let resource_mode = config.runtime.resolve_resource_mode(machine);
    let topology = RuntimeTopology::for_mode(resource_mode, machine.effective_cpus());
    let resolution = resolve_policy(
        &config.advanced.limits,
        &config.runtime.tuning,
        machine,
        resource_mode,
        config.inbounds.len(),
    );
    let fields = resolution
        .fields
        .iter()
        .map(|field| ExplainField {
            field: field.field,
            value: field.value,
            source: field.source.as_str(),
            multiplier: field.multiplier,
            floor: field.floor,
            cap: field.cap,
        })
        .collect::<Vec<_>>();
    ExplainReport {
        schema_version: EXPLAIN_SCHEMA_VERSION,
        machine: ExplainMachine {
            logical_cpus: machine.available_cpus,
            effective_cpus: machine.effective_cpus(),
            fd_soft_limit: machine.fd_soft_limit,
            fd_hard_limit: machine.fd_hard_limit,
            memory_source: machine.memory_source,
            memory_total_bytes: machine.memory_total,
            memory_current_bytes: machine.memory_current,
            cpu_quota_microseconds: machine.cpu_quota_us,
            cpu_period_microseconds: machine.cpu_period_us,
            tenancy_boundary_observable: machine.tenancy_boundary_observable(),
        },
        profile: config.runtime.profile.as_str(),
        resolved_resource_mode: resource_mode.as_str(),
        tuning_mode: config.runtime.tuning.mode().as_str(),
        objective: config.runtime.tuning.objective.as_str(),
        bootstrap: ExplainBootstrap {
            worker_threads: topology.worker_threads.unwrap_or(machine.available_cpus),
            max_blocking_threads: topology.effective_max_blocking_threads(),
            sizing: if topology.worker_threads.is_some() {
                "dedicated"
            } else {
                "tokio-default"
            },
        },
        advisories: advisories(&fields),
        fields,
    }
}

/// Kernel-level suggestions for the operator, advisory only.
///
/// The process never writes sysctls (design §4.4); these point at the
/// settings worth reviewing for the derived plan, nothing more.
fn advisories(fields: &[ExplainField]) -> Vec<String> {
    let value_of = |name: &str| {
        fields
            .iter()
            .find(|field| field.field == name)
            .map_or(0, |field| field.value)
    };
    let mut advisories = vec![
        "kernel tuning is advisory only: the process never writes sysctls, other processes' \
         rlimits, or cgroup files"
            .to_owned(),
    ];
    let max_connections = value_of("resourceGovernor.maxConnections");
    if max_connections > 4_096 {
        advisories.push(format!(
            "net.core.somaxconn and net.ipv4.tcp_max_syn_backlog should comfortably exceed the \
             expected connect burst for a plan admitting {max_connections} concurrent sessions"
        ));
    }
    if value_of("relay.bufferBytes") >= 64 * 1024 {
        advisories.push(
            "net.ipv4.tcp_rmem and net.ipv4.tcp_wmem maxima below the 64 KiB relay buffer tier \
             can throttle large transfers"
                .to_owned(),
        );
    }
    advisories
}

impl fmt::Display for ExplainReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "machine:")?;
        writeln!(
            formatter,
            "  cpus: {} effective ({} logical)",
            self.machine.effective_cpus, self.machine.logical_cpus
        )?;
        writeln!(
            formatter,
            "  descriptors: {} soft / {} hard",
            self.machine.fd_soft_limit, self.machine.fd_hard_limit
        )?;
        writeln!(
            formatter,
            "  memory: {} bytes ({})",
            self.machine.memory_total_bytes, self.machine.memory_source
        )?;
        writeln!(
            formatter,
            "  tenancy boundary observable: {}",
            self.machine.tenancy_boundary_observable
        )?;
        writeln!(formatter, "runtime:")?;
        writeln!(
            formatter,
            "  profile: {} (resolved resource mode: {})",
            self.profile, self.resolved_resource_mode
        )?;
        writeln!(
            formatter,
            "  tuning: mode {} with {} objective",
            self.tuning_mode, self.objective
        )?;
        writeln!(
            formatter,
            "  bootstrap: {} worker threads, {} blocking threads ({})",
            self.bootstrap.worker_threads,
            self.bootstrap.max_blocking_threads,
            self.bootstrap.sizing
        )?;
        writeln!(formatter, "policy:")?;
        for field in &self.fields {
            write!(
                formatter,
                "  {:<42} {:>10}  {}",
                field.field, field.value, field.source
            )?;
            if let Some(multiplier) = field.multiplier {
                write!(formatter, "  x{multiplier}")?;
            }
            match (field.floor, field.cap) {
                (Some(floor), Some(cap)) => write!(formatter, "  [{floor}..{cap}]")?,
                (Some(floor), None) => write!(formatter, "  [>={floor}]")?,
                (None, Some(cap)) => write!(formatter, "  [<={cap}]")?,
                (None, None) => {}
            }
            writeln!(formatter)?;
        }
        if !self.advisories.is_empty() {
            writeln!(formatter, "advisories:")?;
            for advisory in &self.advisories {
                writeln!(formatter, "  - {advisory}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{EXPLAIN_SCHEMA_VERSION, explain_config};
    use crate::runtime::machine::MachineReport;

    fn report() -> MachineReport {
        MachineReport {
            fd_soft_limit: 65_536,
            fd_hard_limit: 1_048_576,
            memlock_soft_limit: 0,
            memlock_hard_limit: 0,
            available_cpus: 4,
            cpu_quota_us: Some(400_000),
            cpu_period_us: Some(100_000),
            cpuset_effective: None,
            memory_source: "cgroup_v2",
            memory_current: None,
            memory_high: None,
            memory_max: Some(4 * 1024 * 1024 * 1024),
            memory_total: 4 * 1024 * 1024 * 1024,
        }
    }

    fn config() -> crate::config::Config {
        crate::config::generate_minimal_config(crate::config::GenerateConfigInput {
            listen: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port: 443,
            target: "www.example.com:443".to_owned(),
            server_name: "www.example.com".to_owned(),
        })
        .expect("configuration must generate")
        .config()
        .clone()
    }

    #[test]
    fn the_explain_report_schema_is_stable() {
        let explanation = explain_config(&config(), &report());
        let json = serde_json::to_value(&explanation).expect("the report must serialize");
        assert_eq!(json["schemaVersion"], EXPLAIN_SCHEMA_VERSION);
        assert_eq!(json["machine"]["effectiveCpus"], 4);
        assert_eq!(json["machine"]["fdSoftLimit"], 65_536);
        assert_eq!(
            json["machine"]["tenancyBoundaryObservable"], true,
            "a finite quota and memory.max make the boundary observable"
        );
        assert_eq!(json["profile"], "auto");
        assert_eq!(json["resolvedResourceMode"], "dedicated");
        assert_eq!(json["tuningMode"], "startup");
        assert_eq!(json["objective"], "balanced");
        assert_eq!(json["bootstrap"]["workerThreads"], 4);
        assert_eq!(json["bootstrap"]["maxBlockingThreads"], 64);
        assert_eq!(json["bootstrap"]["sizing"], "dedicated");
        let fields = json["fields"].as_array().expect("fields must be a list");
        assert_eq!(fields.len(), 21, "every policy field is explained");
        let connections = fields
            .iter()
            .find(|field| field["field"] == "resourceGovernor.maxConnections")
            .expect("maxConnections is explained");
        assert_eq!(connections["source"], "derived");
        assert_eq!(connections["multiplier"], 1.0);
        assert_eq!(connections["floor"], 64);
        let timeouts = fields
            .iter()
            .find(|field| field["field"] == "resourceGovernor.handshakeTimeoutMs")
            .expect("timeouts are explained");
        assert!(
            timeouts.get("multiplier").is_none(),
            "timeouts carry no objective multiplier"
        );
        assert!(json["advisories"].is_array());
    }

    #[test]
    fn the_explain_report_marks_operator_pins() {
        let mut config = config();
        config.advanced.limits.resource_governor.max_connections = 100_000;
        config.runtime.profile = crate::config::RuntimeProfile::Shared;
        let explanation = explain_config(&config, &report());
        let json = serde_json::to_value(&explanation).expect("the report must serialize");
        assert_eq!(json["resolvedResourceMode"], "standard");
        assert_eq!(json["bootstrap"]["sizing"], "tokio-default");
        assert_eq!(json["bootstrap"]["maxBlockingThreads"], 512);
        let fields = json["fields"].as_array().expect("fields must be a list");
        let pinned = fields
            .iter()
            .find(|field| field["field"] == "resourceGovernor.maxConnections")
            .expect("maxConnections is explained");
        assert_eq!(pinned["value"], 100_000);
        assert_eq!(pinned["source"], "override");
        let derived = fields
            .iter()
            .find(|field| field["field"] == "resourceGovernor.maxHandshakes")
            .expect("maxHandshakes is explained");
        assert_eq!(derived["source"], "derived");
    }

    #[test]
    fn the_explain_report_renders_a_human_summary() {
        let explanation = explain_config(&config(), &report());
        let rendered = explanation.to_string();
        assert!(rendered.contains("machine:"));
        assert!(rendered.contains("resolved resource mode: dedicated"));
        assert!(rendered.contains("resourceGovernor.maxConnections"));
        assert!(rendered.contains("advisories:"));
    }
}
