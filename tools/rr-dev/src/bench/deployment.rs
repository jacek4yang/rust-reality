//! Deployment-characterization plan and native suite orchestration.
//!
//! The legacy harness looked like one benchmark but carried five distinct
//! sections. Keeping their dimensions in a typed plan prevents an execution
//! refactor from silently narrowing the formal evidence: a full run still means
//! routing correctness, routing cost, four deployment topologies, the complete
//! one-leg netem matrix, and long-flow relay evidence.

use std::collections::BTreeSet;

use crate::{deploy::netem::LEGS, perf::json_out::Json};

/// One deployment-characterization section, in required execution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    /// Multi-user routing correctness.
    Routing,
    /// Routing decision setup cost.
    Cost,
    /// Direct, NXR, SOCKS5, and Xray deployment topologies.
    Nxr,
    /// Controlled one-leg RTT/loss matrix.
    Rtt,
    /// Large post-auth NXR relay and byte-integrity proof.
    Longflow,
}

impl Section {
    /// Stable evidence name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Routing => "routing",
            Self::Cost => "cost",
            Self::Nxr => "nxr",
            Self::Rtt => "rtt",
            Self::Longflow => "longflow",
        }
    }
}

/// Which reviewed deployment program a plan represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    /// Every correctness, topology, netem, and relay section.
    Full,
    /// The concurrency-one, zero-loss controlled-RTT claim.
    Mechanism,
    /// The full RTT/loss/concurrency robustness matrix only.
    Robustness,
    /// Tiny non-formal local mechanism acceptance.
    Smoke,
}

impl PlanKind {
    /// Parses the CLI spelling.
    ///
    /// # Errors
    ///
    /// Returns the accepted names when the value is unknown.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "full" => Ok(Self::Full),
            "mechanism" => Ok(Self::Mechanism),
            "robustness" => Ok(Self::Robustness),
            "smoke" => Ok(Self::Smoke),
            _ => Err("deployment plan must be full, mechanism, robustness, or smoke".to_owned()),
        }
    }

    /// Stable evidence name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Mechanism => "mechanism",
            Self::Robustness => "robustness",
            Self::Smoke => "smoke",
        }
    }

    /// Whether this plan can make a formal release claim.
    #[must_use]
    pub const fn formal(self) -> bool {
        !matches!(self, Self::Smoke)
    }
}

/// One throughput cell: payload MiB and concurrent transfers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputCell {
    /// Payload size in MiB.
    pub payload_mib: u64,
    /// Concurrent transfers.
    pub concurrency: usize,
}

/// The complete, admitted deployment-characterization dimensions.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Reviewed program.
    pub kind: PlanKind,
    /// Sections in execution order.
    pub sections: Vec<Section>,
    /// Samples for non-netem setup cells.
    pub samples: usize,
    /// Connections in each non-netem setup sample.
    pub connections: usize,
    /// Non-netem setup concurrencies.
    pub concurrencies: Vec<usize>,
    /// Samples in each throughput cell.
    pub throughput_samples: usize,
    /// Required topology throughput cells.
    pub throughput_cells: Vec<ThroughputCell>,
    /// Long-flow payload MiB.
    pub longflow_mib: u64,
    /// Target round-trip delays in milliseconds.
    pub rtts_ms: Vec<u32>,
    /// Per-direction packet loss percentages.
    pub losses_percent: Vec<f64>,
    /// Connections in each controlled-netem setup sample.
    pub rtt_connections: usize,
    /// Controlled-netem setup concurrencies.
    pub rtt_concurrencies: Vec<usize>,
    /// Evaluate the controlled RTT performance claim.
    pub evaluate_netem_performance: bool,
}

impl Plan {
    /// Returns the reviewed dimensions for one program.
    #[must_use]
    pub fn reviewed(kind: PlanKind) -> Self {
        match kind {
            PlanKind::Full => Self {
                kind,
                sections: all_sections(),
                samples: 3,
                connections: 96,
                concurrencies: vec![8, 32],
                throughput_samples: 3,
                throughput_cells: formal_throughput(),
                longflow_mib: 512,
                rtts_ms: vec![1, 10, 50, 100, 200],
                losses_percent: vec![0.0, 0.1, 1.0],
                rtt_connections: 512,
                rtt_concurrencies: vec![1, 8, 32, 128, 512],
                evaluate_netem_performance: true,
            },
            PlanKind::Mechanism => Self {
                kind,
                sections: vec![Section::Rtt],
                samples: 3,
                connections: 96,
                concurrencies: vec![8, 32],
                throughput_samples: 3,
                throughput_cells: formal_throughput(),
                longflow_mib: 512,
                rtts_ms: vec![50, 100, 200],
                losses_percent: vec![0.0],
                rtt_connections: 32,
                rtt_concurrencies: vec![1],
                evaluate_netem_performance: true,
            },
            PlanKind::Robustness => Self {
                kind,
                sections: vec![Section::Rtt],
                samples: 3,
                connections: 96,
                concurrencies: vec![8, 32],
                throughput_samples: 3,
                throughput_cells: formal_throughput(),
                longflow_mib: 512,
                rtts_ms: vec![1, 10, 50, 100, 200],
                losses_percent: vec![0.0, 0.1, 1.0],
                rtt_connections: 512,
                rtt_concurrencies: vec![1, 8, 32, 128, 512],
                evaluate_netem_performance: true,
            },
            PlanKind::Smoke => Self {
                kind,
                sections: vec![Section::Routing, Section::Cost, Section::Nxr, Section::Longflow],
                samples: 1,
                connections: 2,
                concurrencies: vec![2],
                throughput_samples: 1,
                throughput_cells: vec![ThroughputCell {
                    payload_mib: 1,
                    concurrency: 2,
                }],
                longflow_mib: 1,
                rtts_ms: vec![20],
                losses_percent: vec![0.0],
                rtt_connections: 2,
                rtt_concurrencies: vec![1],
                evaluate_netem_performance: false,
            },
        }
    }

    /// Validates the full dimensional contract.
    ///
    /// # Errors
    ///
    /// Returns every detected narrowing or malformed dimension.
    pub fn validate(&self) -> Result<(), String> {
        let expected = Self::reviewed(self.kind);
        if self != &expected {
            return Err(format!(
                "deployment {} dimensions differ from the reviewed plan",
                self.kind.name()
            ));
        }
        let unique: BTreeSet<Section> = self.sections.iter().copied().collect();
        if unique.len() != self.sections.len() {
            return Err("deployment sections contain a duplicate".to_owned());
        }
        Ok(())
    }

    /// Every `(RTT, loss)` profile name in stable order.
    #[must_use]
    pub fn profile_names(&self) -> Vec<String> {
        self.rtts_ms
            .iter()
            .flat_map(|rtt| {
                self.losses_percent.iter().map(move |loss| {
                    format!(
                        "rtt{rtt}-loss{}",
                        loss_token(*loss)
                    )
                })
            })
            .collect()
    }

    /// Every setup evidence label the plan requires.
    #[must_use]
    pub fn setup_labels(&self) -> BTreeSet<String> {
        let mut labels = BTreeSet::new();
        if self.sections.contains(&Section::Cost) {
            labels.extend(
                [
                    "cost-simple",
                    "cost-medium",
                    "cost-complex",
                    "cost-complex-ipifnonmatch",
                    "cost-complex-ipondemand",
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        if self.sections.contains(&Section::Nxr) {
            labels.extend(['a', 'b', 'c', 'd'].map(|name| format!("topo-{name}")));
        }
        if self.sections.contains(&Section::Rtt) {
            for profile in self.profile_names() {
                labels.extend(LEGS.map(|leg| format!("{profile}-{leg}")));
            }
        }
        labels
    }

    /// Renders the admitted plan as durable evidence.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("schemaVersion", Json::Int(1)),
            ("kind", Json::string(self.kind.name())),
            ("formal", Json::Bool(self.kind.formal())),
            (
                "sections",
                Json::Array(self.sections.iter().map(|section| Json::string(section.name())).collect()),
            ),
            ("samples", count(self.samples)),
            ("connectionsPerSample", count(self.connections)),
            ("concurrencies", counts(&self.concurrencies)),
            ("throughputSamples", count(self.throughput_samples)),
            (
                "throughputCells",
                Json::Array(
                    self.throughput_cells
                        .iter()
                        .map(|cell| {
                            Json::object([
                                ("payloadMiB", count(cell.payload_mib)),
                                ("concurrency", count(cell.concurrency)),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("longflowMiB", count(self.longflow_mib)),
            (
                "rttsMs",
                Json::Array(self.rtts_ms.iter().map(|value| count(*value)).collect()),
            ),
            (
                "perDirectionLossPercent",
                Json::Array(self.losses_percent.iter().map(|value| Json::Float(*value)).collect()),
            ),
            ("rttConnectionsPerSample", count(self.rtt_connections)),
            ("rttConcurrencies", counts(&self.rtt_concurrencies)),
            (
                "evaluateNetemPerformance",
                Json::Bool(self.evaluate_netem_performance),
            ),
        ])
    }
}

fn all_sections() -> Vec<Section> {
    vec![Section::Routing, Section::Cost, Section::Nxr, Section::Rtt, Section::Longflow]
}

fn formal_throughput() -> Vec<ThroughputCell> {
    vec![
        ThroughputCell {
            payload_mib: 32,
            concurrency: 1,
        },
        ThroughputCell {
            payload_mib: 32,
            concurrency: 32,
        },
        ThroughputCell {
            payload_mib: 512,
            concurrency: 32,
        },
    ]
}

fn loss_token(loss: f64) -> String {
    if loss.fract() == 0.0 {
        format!("{loss:.0}")
    } else {
        loss.to_string().replace('.', "p")
    }
}

fn count(value: impl TryInto<i64>) -> Json {
    Json::Int(value.try_into().unwrap_or(i64::MAX))
}

fn counts(values: &[usize]) -> Json {
    Json::Array(values.iter().map(|value| count(*value)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_plan_cannot_narrow_the_legacy_matrix() {
        let plan = Plan::reviewed(PlanKind::Full);
        plan.validate().unwrap();
        assert_eq!(plan.sections, all_sections());
        assert_eq!(plan.profile_names().len(), 15);
        assert_eq!(plan.setup_labels().len(), 99);
        assert_eq!(plan.throughput_cells, formal_throughput());
        assert_eq!(plan.rtt_concurrencies, [1, 8, 32, 128, 512]);
    }

    #[test]
    fn focused_formal_programs_retain_their_exact_dimensions() {
        let mechanism = Plan::reviewed(PlanKind::Mechanism);
        assert_eq!(mechanism.sections, [Section::Rtt]);
        assert_eq!(mechanism.profile_names().len(), 3);
        assert_eq!(mechanism.setup_labels().len(), 18);
        assert_eq!(mechanism.rtt_concurrencies, [1]);

        let robustness = Plan::reviewed(PlanKind::Robustness);
        assert_eq!(robustness.sections, [Section::Rtt]);
        assert_eq!(robustness.profile_names().len(), 15);
        assert_eq!(robustness.setup_labels().len(), 90);
    }

    #[test]
    fn smoke_is_small_and_explicitly_non_formal() {
        let smoke = Plan::reviewed(PlanKind::Smoke);
        assert!(!smoke.kind.formal());
        assert!(!smoke.sections.contains(&Section::Rtt));
        assert_eq!(smoke.samples, 1);
        assert_eq!(smoke.connections, 2);
        assert_eq!(smoke.longflow_mib, 1);
        assert!(smoke.to_json().to_python_json().contains("\"formal\": false"));
    }

    #[test]
    fn a_mutated_reviewed_plan_is_rejected() {
        let mut plan = Plan::reviewed(PlanKind::Full);
        plan.rtts_ms.pop();
        assert!(plan.validate().unwrap_err().contains("differ"));
    }
}
