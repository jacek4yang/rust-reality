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
    config::NodeConfig,
    runtime::{
        machine::MachineReport,
        plan::{RuntimeTopology, resolve_policy},
    },
};

/// The schema version of the JSON report. Bump on any shape change.
///
/// Version 3 followed the configuration reset: one override channel collapsed
/// the two operator sources into `operator-pinned`, and the report gained the
/// node's role, the listener set, and the routing summary — the questions an
/// operator actually asks that the policy table alone could not answer.
pub const EXPLAIN_SCHEMA_VERSION: u32 = 3;

/// One complete `runtime explain` report.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainReport {
    /// The report schema version.
    pub schema_version: u32,
    /// The role this node performs.
    pub role: &'static str,
    /// The sockets this configuration would bind.
    pub listeners: Vec<ExplainListener>,
    /// Where traffic goes, when this node routes at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<ExplainRouting>,
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

/// One socket the configuration would bind.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainListener {
    /// The address family policy, as configured.
    pub ip: &'static str,
    /// Every address this endpoint expands to.
    pub addresses: Vec<String>,
    /// Whether startup requires every listed address to bind.
    pub requires_every_address: bool,
}

/// Where traffic goes, summarised.
///
/// The rule lists themselves are not repeated here: they are in the
/// configuration the operator just wrote, and `--route` answers the question
/// they would read them to answer.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainRouting {
    /// The outbound selected when no rule matches.
    pub default_outbound: String,
    /// How names are resolved while rules are evaluated.
    pub strategy: &'static str,
    /// Number of global rules.
    pub rules: usize,
    /// Named policies and how many users select each.
    pub policies: Vec<ExplainPolicy>,
    /// Every outbound name a rule may name, built-ins included.
    pub outbounds: Vec<String>,
    /// Whether any rule names a `geoip:` or `geosite:` condition.
    pub uses_geo_assets: bool,
}

/// One named routing policy and its usage.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExplainPolicy {
    /// The policy name.
    pub name: String,
    /// The outbound selected when none of its rules match.
    pub default_outbound: String,
    /// Number of rules.
    pub rules: usize,
    /// How many users select this policy.
    pub users: usize,
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
pub fn explain_config(node: &NodeConfig, machine: &MachineReport) -> ExplainReport {
    let runtime = node.runtime();
    let resource_mode = crate::runtime::policy::resolve_resource_mode(runtime.profile(), machine);
    let topology = RuntimeTopology::for_mode(resource_mode, machine.effective_cpus());
    let resolution = resolve_policy(
        &runtime.limits(),
        runtime.objective(),
        machine,
        resource_mode,
        node.listeners().len(),
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
        role: node.role().as_str(),
        listeners: node
            .listeners()
            .iter()
            .map(|listener| ExplainListener {
                ip: listener.family().as_str(),
                addresses: listener
                    .bind_addresses()
                    .into_iter()
                    .map(|address| address.to_string())
                    .collect(),
                requires_every_address: listener.family().requires_every_family(),
            })
            .collect(),
        routing: node.as_entry().map(explain_routing),
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
        profile: runtime.profile().as_str(),
        resolved_resource_mode: resource_mode.as_str(),
        tuning_mode: runtime.tuning().as_str(),
        objective: runtime.objective().as_str(),
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

/// Summarises where traffic goes, without repeating the rules themselves.
fn explain_routing(entry: &crate::config::EntryConfig) -> ExplainRouting {
    let routing = &entry.routing;
    let mut outbounds: Vec<String> = crate::config::node::outbound::BUILTIN_OUTBOUNDS
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    outbounds.extend(entry.outbounds().map(|(name, _)| name.clone()));

    let policies = routing
        .policies()
        .map(|(name, policy)| ExplainPolicy {
            name: name.clone(),
            default_outbound: policy.default.clone(),
            rules: policy.rules().len(),
            users: entry
                .users
                .iter()
                .filter(|user| user.policy.as_deref() == Some(name.as_str()))
                .count(),
        })
        .collect();

    ExplainRouting {
        default_outbound: routing.default.clone(),
        strategy: routing.strategy().as_str(),
        rules: routing.rules().len(),
        policies,
        outbounds,
        uses_geo_assets: entry.needs_geo_assets(),
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
    /// Renders the decisions, not the objects.
    ///
    /// The human summary answers what an operator asks: which sockets open,
    /// where traffic goes, what posture this machine resolved to, and which
    /// numbers *they* pinned. The complete field table — every derived value
    /// with its multiplier, floor, and cap — is `--json`, because a wall of
    /// twenty-five numbers buries the four lines that matter.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "role: {}", self.role)?;

        writeln!(formatter, "listeners:")?;
        for listener in &self.listeners {
            let requirement = if listener.requires_every_address {
                "all required"
            } else {
                "at least one"
            };
            writeln!(
                formatter,
                "  {} ({}, {requirement})",
                listener.addresses.join(", "),
                listener.ip
            )?;
        }

        if let Some(routing) = &self.routing {
            writeln!(formatter, "routing:")?;
            writeln!(
                formatter,
                "  default: {} ({} rule{}, strategy {})",
                routing.default_outbound,
                routing.rules,
                if routing.rules == 1 { "" } else { "s" },
                routing.strategy
            )?;
            for policy in &routing.policies {
                writeln!(
                    formatter,
                    "  policy {}: default {} ({} rule{}, {} user{})",
                    policy.name,
                    policy.default_outbound,
                    policy.rules,
                    if policy.rules == 1 { "" } else { "s" },
                    policy.users,
                    if policy.users == 1 { "" } else { "s" }
                )?;
            }
            writeln!(formatter, "  outbounds: {}", routing.outbounds.join(", "))?;
            if routing.uses_geo_assets {
                writeln!(formatter, "  geo data: required by at least one rule")?;
            }
        }

        writeln!(
            formatter,
            "machine: {} effective cpu{} ({} logical), {} descriptors, {} bytes memory ({})",
            self.machine.effective_cpus,
            if self.machine.effective_cpus == 1 {
                ""
            } else {
                "s"
            },
            self.machine.logical_cpus,
            self.machine.fd_soft_limit,
            self.machine.memory_total_bytes,
            self.machine.memory_source
        )?;
        writeln!(
            formatter,
            "posture: profile {} -> {}, tuning {}, objective {}",
            self.profile, self.resolved_resource_mode, self.tuning_mode, self.objective
        )?;
        writeln!(
            formatter,
            "runtime: {} worker threads, {} blocking threads ({})",
            self.bootstrap.worker_threads,
            self.bootstrap.max_blocking_threads,
            self.bootstrap.sizing
        )?;

        let pinned: Vec<&ExplainField> = self
            .fields
            .iter()
            .filter(|field| field.source == "operator-pinned")
            .collect();
        if pinned.is_empty() {
            writeln!(
                formatter,
                "limits: {} values, all derived from the machine (--json for the table)",
                self.fields.len()
            )?;
        } else {
            writeln!(
                formatter,
                "limits: {} pinned, {} derived (--json for the table)",
                pinned.len(),
                self.fields.len() - pinned.len()
            )?;
            for field in pinned {
                writeln!(formatter, "  {} = {}", field.field, field.value)?;
            }
        }

        if !self.advisories.is_empty() {
            writeln!(formatter, "advisories:")?;
            for advisory in &self.advisories {
                writeln!(formatter, "  {advisory}")?;
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

    fn config() -> crate::config::NodeConfig {
        crate::config::node::fixture::entry().into_node()
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
        assert_eq!(fields.len(), 25, "every policy field is explained");
        let connections = fields
            .iter()
            .find(|field| field["field"] == "governor.maxConnections")
            .expect("maxConnections is explained");
        assert_eq!(connections["source"], "startup-derived");
        assert_eq!(connections["multiplier"], 1.0);
        assert_eq!(connections["floor"], 64);
        let timeouts = fields
            .iter()
            .find(|field| field["field"] == "governor.handshakeTimeoutMs")
            .expect("timeouts are explained");
        assert!(
            timeouts.get("multiplier").is_none(),
            "timeouts carry no objective multiplier"
        );
        assert!(json["advisories"].is_array());
    }

    #[test]
    fn the_explain_report_marks_operator_pins() {
        let config =
            crate::config::node::fixture::validated(&crate::config::node::fixture::entry_with(
                r#","runtime":{"profile":"shared","limits":{"maxConnections":100000}}"#,
            ))
            .into_node();
        let explanation = explain_config(&config, &report());
        let json = serde_json::to_value(&explanation).expect("the report must serialize");
        assert_eq!(json["resolvedResourceMode"], "standard");
        assert_eq!(json["bootstrap"]["sizing"], "tokio-default");
        assert_eq!(json["bootstrap"]["maxBlockingThreads"], 512);
        let fields = json["fields"].as_array().expect("fields must be a list");
        let pinned = fields
            .iter()
            .find(|field| field["field"] == "governor.maxConnections")
            .expect("maxConnections is explained");
        assert_eq!(pinned["value"], 100_000);
        assert_eq!(
            pinned["source"], "operator-pinned",
            "there is one override channel, and presence in it is the whole signal"
        );
        let derived = fields
            .iter()
            .find(|field| field["field"] == "governor.maxHandshakes")
            .expect("maxHandshakes is explained");
        assert_eq!(derived["source"], "startup-derived");
    }

    #[test]
    fn the_human_summary_reports_decisions_not_the_field_table() {
        let explanation = explain_config(&config(), &report());
        let rendered = explanation.to_string();

        // The questions an operator asks.
        assert!(rendered.contains("role: entry"), "{rendered}");
        assert!(rendered.contains("listeners:"), "{rendered}");
        assert!(rendered.contains("0.0.0.0:443"), "{rendered}");
        assert!(rendered.contains("routing:"), "{rendered}");
        assert!(rendered.contains("default: direct"), "{rendered}");
        assert!(rendered.contains("outbounds: direct, block"), "{rendered}");
        assert!(rendered.contains("posture:"), "{rendered}");

        // Not the twenty-five-line policy table: that is `--json`.
        assert!(
            rendered.contains("all derived from the machine"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("relay.maxPooledBuffers"),
            "an unpinned derived field must not be listed: {rendered}"
        );
        assert!(
            rendered.lines().count() < 20,
            "the summary must stay readable, got {} lines:\n{rendered}",
            rendered.lines().count()
        );
    }

    #[test]
    fn the_human_summary_lists_exactly_what_the_operator_pinned() {
        let config =
            crate::config::node::fixture::validated(&crate::config::node::fixture::entry_with(
                r#","runtime":{"limits":{"maxConnections":100000,"splice":false}}"#,
            ))
            .into_node();
        let rendered = explain_config(&config, &report()).to_string();

        assert!(rendered.contains("limits: 2 pinned"), "{rendered}");
        assert!(
            rendered.contains("governor.maxConnections = 100000"),
            "{rendered}"
        );
        assert!(rendered.contains("relay.splice = 0"), "{rendered}");
        assert!(
            !rendered.contains("governor.maxHandshakes"),
            "a derived sibling must not be listed: {rendered}"
        );
    }

    #[test]
    fn a_route_query_names_the_rule_that_selected_the_outbound() {
        let config = crate::config::node::fixture::validated(
            &crate::config::node::fixture::entry_without_routing(
                r#""listeners": [{ "port": 443 }],
  "routing": { "default": "direct",
    "rules": [{ "name": "block-private", "ip": ["10.0.0.0/8"], "outbound": "block" }] }"#,
            ),
        )
        .into_node();

        let blocked = super::explain_route(&config, "10.1.2.3:443").expect("the query must answer");
        assert_eq!(blocked.outbound, "block");
        assert_eq!(blocked.matched, "block-private");
        assert_eq!(blocked.scope, "global rule");
        assert!(
            blocked.caveat.is_none(),
            "a configuration with no geo condition needs no caveat"
        );

        let defaulted =
            super::explain_route(&config, "example.com").expect("the query must answer");
        assert_eq!(defaulted.outbound, "direct");
        assert_eq!(defaulted.scope, "policy default");
    }

    #[test]
    fn a_route_query_says_when_it_could_not_evaluate_geo_rules() {
        let config = crate::config::node::fixture::validated(
            &crate::config::node::fixture::entry_without_routing(
                r#""listeners": [{ "port": 443 }],
  "routing": { "default": "direct",
    "rules": [{ "name": "cn", "domain": ["geosite:cn"], "outbound": "block" }] }"#,
            ),
        )
        .into_node();

        let answer =
            super::explain_route(&config, "www.example.cn").expect("the query must answer");

        assert_eq!(
            answer.outbound, "direct",
            "an unevaluated geo rule must not match"
        );
        let caveat = answer
            .caveat
            .expect("the answer must state what it skipped");
        assert!(caveat.contains("geosite:"), "{caveat}");
        assert!(caveat.contains("doctor"), "{caveat}");
    }

    #[test]
    fn a_landing_node_has_no_route_to_explain() {
        let config =
            crate::config::node::fixture::validated(&crate::config::node::fixture::landing_json())
                .into_node();

        let error = super::explain_route(&config, "example.com")
            .expect_err("a landing node does not route");

        assert!(matches!(error, super::RouteQueryError::NotAnEntryNode));
        assert!(error.to_string().contains("egress"), "{error}");
    }

    #[test]
    fn destinations_parse_with_and_without_a_port() {
        use super::split_destination;

        assert_eq!(split_destination("example.com"), Some(("example.com", 443)));
        assert_eq!(
            split_destination("example.com:8443"),
            Some(("example.com", 8443))
        );
        assert_eq!(split_destination("10.0.0.1:80"), Some(("10.0.0.1", 80)));
        assert_eq!(split_destination("2001:db8::1"), Some(("2001:db8::1", 443)));
        assert_eq!(
            split_destination("[2001:db8::1]:8443"),
            Some(("2001:db8::1", 8443))
        );
        assert_eq!(
            split_destination("[2001:db8::1]"),
            Some(("2001:db8::1", 443))
        );
        assert_eq!(split_destination(""), None);
        assert_eq!(split_destination("example.com:notaport"), None);
    }
}

/// The answer to "which outbound would this destination take?".
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteExplanation {
    /// The destination that was asked about.
    pub destination: String,
    /// The identity the answer is for.
    pub user: String,
    /// The outbound the router selected.
    pub outbound: String,
    /// The rule that selected it, or the policy whose default applied.
    pub matched: String,
    /// Whether the match came from a rule or from a default.
    pub scope: &'static str,
    /// Set when the answer excludes rules this query could not evaluate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<&'static str>,
}

impl fmt::Display for RouteExplanation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "{} for {} -> {} ({}, {})",
            self.destination, self.user, self.outbound, self.matched, self.scope
        )?;
        if let Some(caveat) = self.caveat {
            writeln!(formatter, "note: {caveat}")?;
        }
        Ok(())
    }
}

/// A `--route` query failed before an outbound was selected.
#[derive(Debug)]
pub enum RouteQueryError {
    /// The node does not route: a landing sends everything to one egress.
    NotAnEntryNode,
    /// The destination could not be read as `host` or `host:port`.
    InvalidDestination,
    /// Routing did not compile, which `check` would already have rejected.
    Compile(crate::server::routing::RoutingCompileError),
}

impl fmt::Display for RouteQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnEntryNode => formatter.write_str(
                "only an entry node routes; a landing node sends every transfer to its egress",
            ),
            Self::InvalidDestination => {
                formatter.write_str("destination must be a host or host:port")
            }
            Self::Compile(source) => source.fmt(formatter),
        }
    }
}

impl std::error::Error for RouteQueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compile(source) => Some(source),
            Self::NotAnEntryNode | Self::InvalidDestination => None,
        }
    }
}

/// Answers which outbound one destination would take.
///
/// This is offline like the rest of `explain`, which bounds what it can say:
/// geo conditions are evaluated against an empty asset set, because loading
/// them would mean a download. When the configuration has any, the answer
/// carries a caveat rather than quietly reporting a route that a running
/// server would not choose.
///
/// # Errors
///
/// Returns an error when the node does not route, the destination cannot be
/// parsed, or routing does not compile.
pub fn explain_route(
    node: &crate::config::NodeConfig,
    destination: &str,
) -> Result<RouteExplanation, RouteQueryError> {
    use crate::{
        assets::EmptyAssetMatcher,
        protocol::vless::{Address, Destination, UserId},
        server::routing::{RouteContext, RoutingTable},
    };
    use std::sync::Arc;

    let entry = node.as_entry().ok_or(RouteQueryError::NotAnEntryNode)?;
    let (host, port) = split_destination(destination).ok_or(RouteQueryError::InvalidDestination)?;
    let address = host.parse::<std::net::IpAddr>().map_or_else(
        |_| Address::Domain(host.to_ascii_lowercase()),
        |address| match address {
            std::net::IpAddr::V4(v4) => Address::Ipv4(v4),
            std::net::IpAddr::V6(v6) => Address::Ipv6(v6),
        },
    );
    let destination_value = Destination::new(address, port);

    let table = RoutingTable::compile(
        &entry.routing,
        &entry.users,
        Arc::new(EmptyAssetMatcher),
        crate::runtime::ResourceGovernor::new(
            &crate::runtime::policy::ResourceGovernorPolicy::default(),
        ),
    )
    .map_err(RouteQueryError::Compile)?;

    // The first user is the answer's subject; a per-user answer needs the
    // identity, and every identity routes the same way unless it names a
    // policy, which the report already lists.
    let user = entry.users.first().ok_or(RouteQueryError::NotAnEntryNode)?;
    let uuid = uuid::Uuid::parse_str(&user.id).map_err(|_| RouteQueryError::InvalidDestination)?;
    let context = RouteContext {
        user_id: UserId::new(*uuid.as_bytes()),
        inbound_tag: "entry",
        destination: &destination_value,
        resolved_ips: &[],
    };
    let decision = table
        .select(&context)
        .map_err(|_| RouteQueryError::NotAnEntryNode)?;

    Ok(RouteExplanation {
        destination: destination.to_owned(),
        user: user
            .label
            .clone()
            .unwrap_or_else(|| format!("users[0] {}", &user.id[..8])),
        outbound: decision.outbound().to_owned(),
        matched: decision.rule_name().to_owned(),
        scope: decision.scope().as_str(),
        caveat: entry.needs_geo_assets().then_some(
            "geo conditions were not evaluated: `explain` is offline, so a rule naming \
             geoip: or geosite: was treated as not matching. Use `doctor` to load the data.",
        ),
    })
}

/// Splits `host` or `host:port`, defaulting to 443.
fn split_destination(value: &str) -> Option<(&str, u16)> {
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        // A bracketed IPv6 literal, with or without a port.
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => 443,
            _ => tail.strip_prefix(':')?.parse().ok()?,
        };
        return Some((host, port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host, port.parse().ok()?)),
        // A bare IPv6 literal has colons but no port.
        _ => Some((value, 443)),
    }
}
