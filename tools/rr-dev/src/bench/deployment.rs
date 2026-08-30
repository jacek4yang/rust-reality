//! Deployment-characterization plan and native suite orchestration.
//!
//! The legacy harness looked like one benchmark but carried five distinct
//! sections. Keeping their dimensions in a typed plan prevents an execution
//! refactor from silently narrowing the formal evidence: a full run still means
//! routing correctness, routing cost, four deployment topologies, the complete
//! one-leg netem matrix, and long-flow relay evidence.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read as _, Write as _},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use crate::{
    deploy::netem::LEGS,
    hash,
    perf::{json_in, json_in::Value, json_out::Json},
    process::Tool,
};

use super::suites;

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

#[derive(Debug)]
pub(crate) struct RoutingConfig {
    pub(crate) json: String,
    pub(crate) short_ids: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct RoutingConfigInput<'a> {
    pub(crate) base: &'a str,
    pub(crate) uuids: &'a [String],
    pub(crate) origin_a_port: u16,
    pub(crate) socks_b_port: u16,
    pub(crate) blocked_port: u16,
    pub(crate) geosite_label: &'a str,
    pub(crate) assets: &'a Path,
}

/// Builds the exact four-user routing correctness policy without replacing any
/// unrelated generated configuration fields.
#[expect(
    clippy::too_many_lines,
    reason = "the reviewed routing policy stays visibly contiguous and exact"
)]
pub(crate) fn routing_config(input: &RoutingConfigInput<'_>) -> Result<RoutingConfig, String> {
    if input.uuids.len() != 4 {
        return Err("routing correctness requires exactly four UUIDs".to_owned());
    }
    let mut root = root_object(input.base)?;
    let base_client = first_client(&root)?.clone();
    let clients = clients_with_owned_short_ids(&base_client, input.uuids, Some("proof"))?;
    let short_ids = clients
        .iter()
        .map(|client| {
            client
                .array_field("client", "shortIds")
                .map_err(|error| error.to_string())?
                .first()
                .ok_or_else(|| "generated routing client has no short ID".to_owned())?
                .as_str("client.shortIds[0]")
                .map(str::to_owned)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    replace_clients(&mut root, clients)?;
    root.insert(
        "outbounds".to_owned(),
        Value::Array(vec![
            object([("protocol", string("direct")), ("tag", string("direct"))]),
            object([
                ("protocol", string("blackhole")),
                ("tag", string("block")),
                (
                    "settings",
                    object([("responseDelayMs", number(0))]),
                ),
            ]),
            object([
                ("protocol", string("socks5")),
                ("tag", string("via-socks-b")),
                (
                    "settings",
                    object([
                        ("address", string("127.0.0.1")),
                        ("port", number(u64::from(input.socks_b_port))),
                    ]),
                ),
            ]),
        ]),
    );
    root.insert(
        "routing".to_owned(),
        object([
            ("domainStrategy", string("IPIfNonMatch")),
            (
                "globalRules",
                Value::Array(vec![
                    rule(
                        "global-block-domain",
                        "block",
                        [("domain", strings(["full:blocked.example"]))],
                    ),
                    rule(
                        "global-block-geosite",
                        "block",
                        [("domain", strings([format!("geosite:{}", input.geosite_label)]))],
                    ),
                    rule(
                        "global-block-port",
                        "block",
                        [("port", strings([input.blocked_port.to_string()]))],
                    ),
                ]),
            ),
            (
                "users",
                Value::Array(vec![
                    object([
                        ("name", string("group-alpha")),
                        ("userIds", strings(input.uuids[..2].iter().cloned())),
                        ("defaultOutbound", string("block")),
                        (
                            "rules",
                            Value::Array(vec![
                                rule(
                                    "alpha-allow-origin-a-by-domain",
                                    "direct",
                                    [
                                        ("domain", strings(["full:localhost"])),
                                        ("port", strings([input.origin_a_port.to_string()])),
                                    ],
                                ),
                                rule(
                                    "alpha-allow-origin-a-by-ip",
                                    "direct",
                                    [
                                        ("ip", strings(["127.0.0.1"])),
                                        ("port", strings([input.origin_a_port.to_string()])),
                                    ],
                                ),
                                rule(
                                    "alpha-late-block-loopback-rest",
                                    "block",
                                    [("ip", strings(["127.0.0.0/8"]))],
                                ),
                            ]),
                        ),
                    ]),
                    object([
                        ("name", string("group-beta")),
                        ("userIds", strings(input.uuids[2..].iter().cloned())),
                        ("defaultOutbound", string("via-socks-b")),
                        (
                            "rules",
                            Value::Array(vec![rule(
                                "beta-block-private-geoip",
                                "block",
                                [("ip", strings(["geoip:private"]))],
                            )]),
                        ),
                    ]),
                ]),
            ),
        ]),
    );
    root.insert("log".to_owned(), object([("level", string("warn"))]));
    let assets = root
        .entry("assets".to_owned())
        .or_insert_with(|| object(std::iter::empty::<(&str, Value)>()));
    let Value::Object(assets) = assets else {
        return Err("generated routing config assets is not an object".to_owned());
    };
    assets.insert(
        "cacheDirectory".to_owned(),
        string(input.assets.display().to_string()),
    );
    assets.insert("requestTimeoutSeconds".to_owned(), number(15));
    Ok(RoutingConfig {
        json: suites::render_compact(&Value::Object(root)),
        short_ids,
    })
}

#[derive(Debug)]
pub(crate) struct ScaleConfigInput<'a> {
    pub(crate) base: &'a str,
    pub(crate) uuids: &'a [String],
    pub(crate) rules: usize,
    pub(crate) global_rules: usize,
    pub(crate) with_ip: bool,
    pub(crate) strategy: &'a str,
    pub(crate) assets: &'a Path,
}

/// Builds one routing-cost scale while preserving the generated listener and
/// REALITY identity around the replaced routing policy.
pub(crate) fn scale_config(input: &ScaleConfigInput<'_>) -> Result<String, String> {
    if input.uuids.is_empty() {
        return Err("routing-cost scale requires at least one UUID".to_owned());
    }
    if !matches!(input.strategy, "AsIs" | "IPIfNonMatch" | "IPOnDemand") {
        return Err(format!("unknown routing domain strategy: {}", input.strategy));
    }
    let mut root = root_object(input.base)?;
    let base_client = first_client(&root)?.clone();
    let clients = clients_with_owned_short_ids(&base_client, input.uuids, None)?;
    replace_clients(&mut root, clients)?;
    root.insert(
        "outbounds".to_owned(),
        Value::Array(vec![
            object([("protocol", string("direct")), ("tag", string("direct"))]),
            object([
                ("protocol", string("blackhole")),
                ("tag", string("block")),
                ("settings", object([("responseDelayMs", number(0))])),
            ]),
        ]),
    );
    let mut users = vec![object([
        ("name", string("measured")),
        ("userIds", strings([input.uuids[0].clone()])),
        ("defaultOutbound", string("direct")),
        ("rules", Value::Array(scale_rules(input.rules, input.with_ip, ""))),
    ])];
    if input.uuids.len() > 1 {
        users.push(object([
            ("name", string("bulk")),
            ("userIds", strings(input.uuids[1..].iter().cloned())),
            ("defaultOutbound", string("block")),
            ("rules", Value::Array(Vec::new())),
        ]));
    }
    root.insert(
        "routing".to_owned(),
        object([
            ("domainStrategy", string(input.strategy)),
            (
                "globalRules",
                Value::Array(scale_rules(input.global_rules, input.with_ip, "global-")),
            ),
            ("users", Value::Array(users)),
        ]),
    );
    root.insert("log".to_owned(), object([("level", string("warn"))]));
    let assets = root
        .entry("assets".to_owned())
        .or_insert_with(|| object(std::iter::empty::<(&str, Value)>()));
    let Value::Object(assets) = assets else {
        return Err("generated routing-cost config assets is not an object".to_owned());
    };
    assets.insert(
        "cacheDirectory".to_owned(),
        string(input.assets.display().to_string()),
    );
    Ok(suites::render_compact(&Value::Object(root)))
}

fn root_object(raw: &str) -> Result<BTreeMap<String, Value>, String> {
    match json_in::parse(raw)
        .map_err(|error| format!("generated rust config is invalid JSON: {error}"))?
    {
        Value::Object(root) => Ok(root),
        _ => Err("generated rust config is not an object".to_owned()),
    }
}

fn first_client(root: &BTreeMap<String, Value>) -> Result<&Value, String> {
    root.get("inbounds")
        .ok_or_else(|| "generated config has no inbounds".to_owned())?
        .as_array("inbounds")
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated config has no first inbound".to_owned())?
        .field("inbounds[0]", "settings")
        .and_then(|settings| settings.array_field("inbounds[0].settings", "clients"))
        .map_err(|error| error.to_string())?
        .first()
        .ok_or_else(|| "generated config has no base client".to_owned())
}

fn replace_clients(root: &mut BTreeMap<String, Value>, clients: Vec<Value>) -> Result<(), String> {
    let Some(Value::Array(inbounds)) = root.get_mut("inbounds") else {
        return Err("generated config has no inbounds array".to_owned());
    };
    let Some(Value::Object(inbound)) = inbounds.first_mut() else {
        return Err("generated config has no first inbound object".to_owned());
    };
    let Some(Value::Object(settings)) = inbound.get_mut("settings") else {
        return Err("generated config has no first inbound settings object".to_owned());
    };
    settings.insert("clients".to_owned(), Value::Array(clients));
    Ok(())
}

fn clients_with_owned_short_ids(
    base: &Value,
    uuids: &[String],
    email_prefix: Option<&str>,
) -> Result<Vec<Value>, String> {
    let base_short_ids = base
        .array_field("baseClient", "shortIds")
        .map_err(|error| error.to_string())?;
    if base_short_ids.is_empty() {
        return Err("base VLESS client must contain at least one short ID".to_owned());
    }
    let mut used = BTreeSet::new();
    let mut first_ids = Vec::with_capacity(base_short_ids.len());
    for (index, value) in base_short_ids.iter().enumerate() {
        let short_id = value
            .as_str(&format!("baseClient.shortIds[{index}]"))
            .map_err(|error| error.to_string())?
            .to_owned();
        if !used.insert(short_id.to_ascii_lowercase()) {
            return Err("base VLESS client contains duplicate short IDs".to_owned());
        }
        first_ids.push(short_id);
    }
    uuids
        .iter()
        .enumerate()
        .map(|(index, uuid)| {
            let short_ids = if index == 0 {
                first_ids.clone()
            } else {
                let short_id = (0_u16..=255)
                    .map(|salt| hash::sha256_hex(format!("{uuid}:{salt}").as_bytes())[..16].to_owned())
                    .find(|candidate| !used.contains(&candidate.to_ascii_lowercase()))
                    .ok_or_else(|| "could not derive a unique short ID for VLESS client".to_owned())?;
                used.insert(short_id.to_ascii_lowercase());
                vec![short_id]
            };
            let mut client = BTreeMap::from([
                ("flow".to_owned(), string("xtls-rprx-vision")),
                ("id".to_owned(), string(uuid)),
                ("shortIds".to_owned(), strings(short_ids)),
            ]);
            if let Some(prefix) = email_prefix {
                client.insert("email".to_owned(), string(format!("{prefix}-{index}")));
            }
            Ok(Value::Object(client))
        })
        .collect()
}

fn scale_rules(count: usize, with_ip: bool, prefix: &str) -> Vec<Value> {
    (0..count)
        .map(|index| {
            let kind = index % if with_ip { 5 } else { 4 };
            let (suffix, field, value) = match kind {
                0 => ("full", "domain", format!("full:host{index}.scale-example.test")),
                1 => ("keyword", "domain", format!("keyword:needle-{index}-scale")),
                2 => (
                    "regexp",
                    "domain",
                    format!(r"regexp:^cdn-[0-9]+\.scale-{index}\.test$"),
                ),
                3 => (
                    "port",
                    "port",
                    format!("{}-{}", 20_000 + index % 1000, 21_000 + index % 1000),
                ),
                _ => ("cidr", "ip", format!("10.{}.0.0/16", index % 250)),
            };
            rule(
                &format!("{prefix}r{index}-{suffix}"),
                "block",
                [(field, strings([value]))],
            )
        })
        .collect()
}

fn rule<const N: usize>(name: &str, outbound: &str, fields: [(&str, Value); N]) -> Value {
    let mut rule = BTreeMap::from([
        ("name".to_owned(), string(name)),
        ("outbound".to_owned(), string(outbound)),
    ]);
    rule.extend(fields.into_iter().map(|(key, value)| (key.to_owned(), value)));
    Value::Object(rule)
}

fn object<K: Into<String>>(entries: impl IntoIterator<Item = (K, Value)>) -> Value {
    Value::Object(entries.into_iter().map(|(key, value)| (key.into(), value)).collect())
}

fn string(value: impl Into<String>) -> Value {
    Value::Str(value.into())
}

fn strings(values: impl IntoIterator<Item = impl Into<String>>) -> Value {
    Value::Array(values.into_iter().map(|value| string(value.into())).collect())
}

fn number(value: u64) -> Value {
    Value::Number(value.to_string())
}

/// Expected outcome of one routing proof case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteExpectation {
    /// The connection must be refused before an HTTP response arrives.
    Blocked,
    /// The response body must have this exact SHA-256.
    Sha256(String),
}

/// One `(user, destination)` routing proof case.
#[derive(Debug, Clone)]
pub struct RouteCase {
    /// Stable user UUID.
    pub uuid: String,
    /// User group name.
    pub group: String,
    /// Rule/default behavior under test.
    pub label: String,
    /// This user's Xray SOCKS listener.
    pub socks_port: u16,
    /// Destination host presented to the server.
    pub host: String,
    /// Destination port presented to the server.
    pub port: u16,
    /// HTTP path.
    pub path: String,
    /// Required classification.
    pub expect: RouteExpectation,
}

/// Observed result of one routing proof case.
#[derive(Debug, Clone)]
pub struct RouteResult {
    /// Original case.
    pub case: RouteCase,
    /// `blocked`, `error`, or `sha256:<digest>`.
    pub observed: String,
    /// Bounded failure detail.
    pub detail: String,
    /// End-to-end case time.
    pub seconds: f64,
    /// Whether observed equals expected.
    pub passed: bool,
}

impl RouteResult {
    /// Renders the legacy per-case evidence shape.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let expected = match &self.case.expect {
            RouteExpectation::Blocked => "blocked".to_owned(),
            RouteExpectation::Sha256(digest) => digest.clone(),
        };
        Json::object([
            ("uuid", Json::string(&self.case.uuid)),
            ("group", Json::string(&self.case.group)),
            ("label", Json::string(&self.case.label)),
            (
                "destination",
                Json::string(format!("{}:{}", self.case.host, self.case.port)),
            ),
            ("expected", Json::string(expected)),
            ("observed", Json::string(&self.observed)),
            ("detail", Json::string(&self.detail)),
            ("seconds", Json::Float(self.seconds)),
            ("pass", Json::Bool(self.passed)),
        ])
    }
}

/// Probes every routing case without retrying failures.
#[must_use]
pub fn probe_routes(cases: &[RouteCase]) -> Vec<RouteResult> {
    cases.iter().cloned().map(probe_route).collect()
}

fn probe_route(case: RouteCase) -> RouteResult {
    let started = Instant::now();
    let result = socks_http_body(&case);
    let (observed, detail) = match result {
        Ok(body) => (format!("sha256:{}", hash::sha256_hex(&body)), String::new()),
        Err(error) if error.blocked => ("blocked".to_owned(), error.detail),
        Err(error) => ("error".to_owned(), error.detail),
    };
    let passed = match &case.expect {
        RouteExpectation::Blocked => observed == "blocked",
        RouteExpectation::Sha256(expected) => {
            observed == *expected || observed == format!("sha256:{expected}")
        }
    };
    RouteResult {
        case,
        observed,
        detail,
        seconds: started.elapsed().as_secs_f64(),
        passed,
    }
}

struct RouteError {
    blocked: bool,
    detail: String,
}

fn socks_http_body(case: &RouteCase) -> Result<Vec<u8>, RouteError> {
    let mut stream = TcpStream::connect_timeout(
        &SocketAddr::from((Ipv4Addr::LOCALHOST, case.socks_port)),
        Duration::from_secs(30),
    )
    .map_err(route_blocked)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(route_error)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(route_error)?;
    stream.write_all(&[5, 1, 0]).map_err(route_error)?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).map_err(route_error)?;
    if greeting != [5, 0] {
        return Err(route_blocked("SOCKS greeting rejected"));
    }
    let mut connect = vec![5, 1, 0];
    if let Ok(address) = case.host.parse::<Ipv4Addr>() {
        connect.push(1);
        connect.extend_from_slice(&address.octets());
    } else {
        let host = case.host.as_bytes();
        let length = u8::try_from(host.len()).map_err(|_| route_error("domain too long"))?;
        connect.extend([3, length]);
        connect.extend_from_slice(host);
    }
    connect.extend_from_slice(&case.port.to_be_bytes());
    stream.write_all(&connect).map_err(route_error)?;
    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).map_err(route_blocked)?;
    if reply[1] != 0 {
        return Err(route_blocked(format!("SOCKS connect rejected ({})", reply[1])));
    }
    let bound = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8];
            stream.read_exact(&mut length).map_err(route_error)?;
            usize::from(length[0])
        }
        _ => return Err(route_error("SOCKS reply has unknown address type")),
    };
    let mut discard = vec![0_u8; bound + 2];
    stream.read_exact(&mut discard).map_err(route_error)?;
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        case.path, case.host, case.port
    );
    stream.write_all(request.as_bytes()).map_err(route_error)?;
    let mut response = Vec::new();
    stream
        .take(8 * 1024 * 1024)
        .read_to_end(&mut response)
        .map_err(route_error)?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| route_error("HTTP response has no header terminator"))?;
    let (head, body) = response.split_at(split + 4);
    let status = std::str::from_utf8(head)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1));
    if status != Some("200") {
        return Err(route_error(format!("HTTP status {status:?}")));
    }
    Ok(body.to_vec())
}

fn route_blocked(error: impl std::fmt::Display) -> RouteError {
    RouteError {
        blocked: true,
        detail: bounded_detail(error),
    }
}

fn route_error(error: impl std::fmt::Display) -> RouteError {
    RouteError {
        blocked: false,
        detail: bounded_detail(error),
    }
}

fn bounded_detail(error: impl std::fmt::Display) -> String {
    error.to_string().chars().take(200).collect()
}

/// Routing correctness cardinality/verdict document.
#[must_use]
pub fn routing_summary(results: &[RouteResult]) -> Json {
    let passed = results.iter().filter(|result| result.passed).count();
    Json::object([
        ("cases", count(results.len())),
        ("passed", count(passed)),
        ("failed", count(results.len().saturating_sub(passed))),
        (
            "verdict",
            Json::string(if passed == results.len() { "PASS" } else { "FAIL" }),
        ),
    ])
}

/// One SOCKS-mediated throughput program.
#[derive(Debug, Clone)]
pub struct SocksThroughputPlan {
    /// Evidence label.
    pub label: String,
    /// Local Xray SOCKS listener.
    pub socks_port: u16,
    /// Exact payload URL.
    pub url: String,
    /// Payload MiB.
    pub payload_mib: u64,
    /// Samples for each concurrency.
    pub samples: usize,
    /// Concurrency levels.
    pub concurrencies: Vec<usize>,
    /// Exact payload SHA-256.
    pub expected_sha256: String,
    /// Ephemeral directory for the first-transfer integrity file.
    pub workspace: PathBuf,
}

/// One SOCKS throughput cell result.
#[derive(Debug, Clone)]
pub struct SocksThroughputRow {
    /// Evidence label.
    pub label: String,
    /// Concurrent transfers.
    pub concurrency: usize,
    /// Sample index.
    pub sample_index: usize,
    /// Wall-clock seconds.
    pub wall_seconds: f64,
    /// Per-request seconds.
    pub per_request_seconds: Vec<f64>,
    /// Aggregate MiB/s.
    pub throughput_mib_per_second: f64,
    /// Whether this row performed and passed exact integrity.
    pub integrity: Option<bool>,
}

impl SocksThroughputRow {
    /// Renders the deployment-driver row shape.
    #[must_use]
    pub fn to_json(&self) -> Json {
        Json::object([
            ("label", Json::string(&self.label)),
            ("concurrency", count(self.concurrency)),
            ("sampleIndex", count(self.sample_index)),
            ("wallSeconds", Json::Float(self.wall_seconds)),
            ("transfers", count(self.per_request_seconds.len())),
            (
                "perRequestSeconds",
                Json::Array(
                    self.per_request_seconds
                        .iter()
                        .copied()
                        .map(Json::Float)
                        .collect(),
                ),
            ),
            (
                "throughputMiBPerSecond",
                Json::Float(self.throughput_mib_per_second),
            ),
            (
                "integrity",
                Json::string(match self.integrity {
                    Some(true) => "pass",
                    Some(false) => "fail",
                    None => "skip",
                }),
            ),
        ])
    }
}

/// Runs every SOCKS throughput cell and requires exact byte integrity.
///
/// # Errors
///
/// Returns the first failed transfer or integrity mismatch.
pub fn run_socks_throughput(
    plan: &SocksThroughputPlan,
) -> Result<Vec<SocksThroughputRow>, String> {
    if plan.samples == 0 || plan.concurrencies.is_empty() || plan.payload_mib == 0 {
        return Err("SOCKS throughput dimensions must be positive".to_owned());
    }
    let mut rows = Vec::with_capacity(plan.samples * plan.concurrencies.len());
    for concurrency in &plan.concurrencies {
        for sample_index in 0..plan.samples {
            rows.push(run_socks_throughput_sample(plan, *concurrency, sample_index)?);
        }
    }
    Ok(rows)
}

fn run_socks_throughput_sample(
    plan: &SocksThroughputPlan,
    concurrency: usize,
    sample_index: usize,
) -> Result<SocksThroughputRow, String> {
    if concurrency == 0 {
        return Err("SOCKS throughput concurrency must be positive".to_owned());
    }
    let verify = plan.workspace.join(format!(
        ".verify-{}-c{concurrency}-s{sample_index}.bin",
        plan.label
    ));
    let next = AtomicUsize::new(0);
    let started = Instant::now();
    let results = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..concurrency)
            .map(|_| {
                let next = &next;
                let verify = &verify;
                scope.spawn(move || {
                    let mut mine = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= concurrency {
                            break;
                        }
                        let output = (sample_index == 0 && index == 0).then_some(verify.as_path());
                        mine.push(curl_socks(plan, output));
                    }
                    mine
                })
            })
            .collect();
        let mut results = Vec::with_capacity(concurrency);
        for handle in handles {
            results.extend(handle.join().map_err(|_| "throughput worker panicked")?);
        }
        Ok::<_, &str>(results)
    })
    .map_err(str::to_owned)?;
    let per_request_seconds: Vec<f64> = results.into_iter().collect::<Result<_, _>>()?;
    let integrity = if sample_index == 0 {
        let observed = hash::sha256_file(&verify)?;
        let _ = std::fs::remove_file(&verify);
        if observed != plan.expected_sha256 {
            return Err(format!(
                "{} c{concurrency} integrity mismatch: expected {}, observed {observed}",
                plan.label, plan.expected_sha256
            ));
        }
        Some(true)
    } else {
        None
    };
    let wall_seconds = started.elapsed().as_secs_f64();
    #[expect(clippy::cast_precision_loss, reason = "bounded benchmark dimensions")]
    let throughput_mib_per_second =
        (plan.payload_mib as f64) * (concurrency as f64) / wall_seconds;
    Ok(SocksThroughputRow {
        label: plan.label.clone(),
        concurrency,
        sample_index,
        wall_seconds,
        per_request_seconds,
        throughput_mib_per_second,
        integrity,
    })
}

fn curl_socks(plan: &SocksThroughputPlan, output: Option<&Path>) -> Result<f64, String> {
    let expected_bytes = plan.payload_mib * 1024 * 1024;
    let mut curl = Tool::new("curl");
    for name in [
        "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
        "NO_PROXY", "no_proxy",
    ] {
        curl = curl.env(name, "");
    }
    let outcome = curl
        .args([
            "--fail".to_owned(),
            "--silent".to_owned(),
            "--show-error".to_owned(),
            "--max-time".to_owned(),
            "300".to_owned(),
            "--socks5-hostname".to_owned(),
            format!("127.0.0.1:{}", plan.socks_port),
            "--output".to_owned(),
            output.map_or_else(|| "/dev/null".to_owned(), |path| path.display().to_string()),
            "--write-out".to_owned(),
            "%{size_download} %{time_total}".to_owned(),
            plan.url.clone(),
        ])
        .probe()
        .map_err(|error| format!("could not run throughput curl: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "throughput curl exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let mut fields = outcome.trimmed_stdout().split_whitespace();
    let bytes = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| "throughput curl returned no byte count".to_owned())?;
    let seconds = fields
        .next()
        .and_then(|value| value.parse::<f64>().ok())
        .ok_or_else(|| "throughput curl returned no duration".to_owned())?;
    if bytes != expected_bytes {
        return Err(format!("throughput short read: {bytes} of {expected_bytes}"));
    }
    Ok(seconds)
}

/// Aggregated long-flow relay log evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEvidence {
    /// Availability by backend name.
    pub backend_report: BTreeMap<String, bool>,
    /// Accepted connections.
    pub accepted: usize,
    /// Cleanly closed connections.
    pub closed: usize,
    /// Rejected connections.
    pub rejected: usize,
    /// Completion events.
    pub completed: usize,
    /// Backends named on completion events.
    pub completed_backends: BTreeSet<String>,
    /// Completion events missing backend attribution.
    pub missing_backend: usize,
}

impl RelayEvidence {
    /// Whether the legacy splice-evidence contract passes.
    #[must_use]
    pub fn passes(&self, expected: &str) -> bool {
        self.backend_report.get(expected) == Some(&true)
            && self.accepted >= 1
            && self.closed >= 1
            && self.rejected == 0
            && self.missing_backend == 0
            && (self.completed == 0
                || self.completed_backends == BTreeSet::from([expected.to_owned()]))
    }

    /// Renders the long-flow report, including the no-per-connection caveat.
    #[must_use]
    pub fn to_json(&self, log: &Path, expected: &str) -> Json {
        let emitted = self.completed > 0;
        Json::object([
            ("log", Json::string(log.display().to_string())),
            ("expectedBackend", Json::string(expected)),
            (
                "backendReport",
                Json::object(
                    self.backend_report
                        .iter()
                        .map(|(name, available)| (name.clone(), Json::Bool(*available))),
                ),
            ),
            (
                "expectedBackendAvailable",
                Json::Bool(self.backend_report.get(expected) == Some(&true)),
            ),
            ("connectionAccepted", count(self.accepted)),
            ("connectionClosed", count(self.closed)),
            ("connectionRejected", count(self.rejected)),
            ("connectionCompletedEvents", count(self.completed)),
            (
                "relayBackends",
                Json::Array(
                    self.completed_backends
                        .iter()
                        .map(Json::string)
                        .collect(),
                ),
            ),
            ("eventsMissingRelayBackend", count(self.missing_backend)),
            (
                "perConnectionBackendEvidence",
                Json::string(if emitted { "emitted" } else { "not-emitted" }),
            ),
            (
                "verdict",
                Json::string(if self.passes(expected) { "PASS" } else { "FAIL" }),
            ),
        ])
    }
}

/// Parses structured server logs into the long-flow relay contract.
#[must_use]
pub fn relay_evidence(log: &str) -> RelayEvidence {
    let mut evidence = RelayEvidence {
        backend_report: BTreeMap::new(),
        accepted: 0,
        closed: 0,
        rejected: 0,
        completed: 0,
        completed_backends: BTreeSet::new(),
        missing_backend: 0,
    };
    for value in log.lines().filter_map(|line| json_in::parse(line.trim()).ok()) {
        let event = value.optional("event").and_then(json_string);
        match event {
            Some("relay_backend_report") => {
                if let Some(json_in::Value::Array(backends)) = value.optional("backends") {
                    for backend in backends {
                        if let (Some(name), Some(available)) = (
                            backend.optional("backend").and_then(json_string),
                            backend.optional("available").and_then(json_bool),
                        ) {
                            evidence.backend_report.insert(name.to_owned(), available);
                        }
                    }
                }
            }
            Some("connection_accepted") => evidence.accepted += 1,
            Some("connection_closed") => evidence.closed += 1,
            Some("connection_rejected") => evidence.rejected += 1,
            Some("connection_completed") => {
                evidence.completed += 1;
                if let Some(backend) = value.optional("relay_backend").and_then(json_string) {
                    evidence.completed_backends.insert(backend.to_owned());
                } else {
                    evidence.missing_backend += 1;
                }
            }
            _ => {}
        }
    }
    evidence
}

fn json_string(value: &json_in::Value) -> Option<&str> {
    match value {
        json_in::Value::Str(value) => Some(value),
        _ => None,
    }
}

const fn json_bool(value: &json_in::Value) -> Option<bool> {
    match value {
        json_in::Value::Bool(value) => Some(*value),
        _ => None,
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

    fn generated_base() -> &'static str {
        r#"{
          "sentinel":"keep",
          "log":{"level":"info","format":"json"},
          "assets":{"cacheDirectory":"old","sentinel":true},
          "inbounds":[{
            "port":8443,
            "settings":{"clients":[{
              "id":"base","flow":"xtls-rprx-vision","shortIds":["0123456789abcdef"]
            }]},
            "streamSettings":{"sentinel":true}
          }],
          "outbounds":[{"protocol":"direct","tag":"old-direct"}],
          "routing":{"users":[{"name":"old","userIds":["base"]}]}
        }"#
    }

    fn uuids(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
            .collect()
    }

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

    #[test]
    fn routing_config_replaces_only_the_owned_policy_subtrees() {
        let uuids = uuids(4);
        let config = routing_config(&RoutingConfigInput {
            base: generated_base(),
            uuids: &uuids,
            origin_a_port: 8080,
            socks_b_port: 1080,
            blocked_port: 9666,
            geosite_label: "google",
            assets: Path::new("/tmp/assets"),
        })
        .unwrap();
        assert_eq!(config.short_ids.len(), 4);
        assert_eq!(config.short_ids[0], "0123456789abcdef");
        assert_eq!(config.short_ids.iter().collect::<BTreeSet<_>>().len(), 4);
        let value = json_in::parse(&config.json).unwrap();
        assert_eq!(value.str_field("", "sentinel").unwrap(), "keep");
        assert!(
            value
                .array_field("", "inbounds")
                .unwrap()[0]
                .field("inbounds[0]", "streamSettings")
                .unwrap()
                .field("inbounds[0].streamSettings", "sentinel")
                .unwrap()
                .as_bool("sentinel")
                .unwrap()
        );
        let clients = value
            .array_field("", "inbounds")
            .unwrap()[0]
            .field("inbounds[0]", "settings")
            .unwrap()
            .array_field("inbounds[0].settings", "clients")
            .unwrap();
        assert_eq!(clients.len(), 4);
        let routing = value.field("", "routing").unwrap();
        assert_eq!(routing.array_field("routing", "users").unwrap().len(), 2);
        assert_eq!(routing.array_field("routing", "globalRules").unwrap().len(), 3);
        assert!(
            value
                .field("", "assets")
                .unwrap()
                .field("assets", "sentinel")
                .unwrap()
                .as_bool("assets.sentinel")
                .unwrap()
        );
    }

    #[test]
    fn routing_cost_scale_retains_generated_identity_and_exact_dimensions() {
        let uuids = uuids(5);
        let json = scale_config(&ScaleConfigInput {
            base: generated_base(),
            uuids: &uuids,
            rules: 16,
            global_rules: 4,
            with_ip: true,
            strategy: "IPOnDemand",
            assets: Path::new("/tmp/scale-assets"),
        })
        .unwrap();
        let value = json_in::parse(&json).unwrap();
        assert_eq!(value.str_field("", "sentinel").unwrap(), "keep");
        let clients = value
            .array_field("", "inbounds")
            .unwrap()[0]
            .field("inbounds[0]", "settings")
            .unwrap()
            .array_field("inbounds[0].settings", "clients")
            .unwrap();
        assert_eq!(clients.len(), 5);
        let routing = value.field("", "routing").unwrap();
        assert_eq!(
            routing.str_field("routing", "domainStrategy").unwrap(),
            "IPOnDemand"
        );
        let users = routing.array_field("routing", "users").unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].array_field("routing.users[0]", "rules").unwrap().len(), 16);
        let global = routing.array_field("routing", "globalRules").unwrap();
        assert_eq!(global.len(), 4);
        assert!(
            global
                .iter()
                .all(|rule| rule.str_field("rule", "name").unwrap().starts_with("global-"))
        );
    }

    #[test]
    fn route_summary_requires_every_case() {
        let case = RouteCase {
            uuid: "u".to_owned(),
            group: "alpha".to_owned(),
            label: "block".to_owned(),
            socks_port: 1,
            host: "blocked.example".to_owned(),
            port: 80,
            path: "/payload-1.bin".to_owned(),
            expect: RouteExpectation::Blocked,
        };
        let results = vec![RouteResult {
            case,
            observed: "blocked".to_owned(),
            detail: String::new(),
            seconds: 0.1,
            passed: true,
        }];
        assert!(routing_summary(&results).to_python_json().contains("\"verdict\": \"PASS\""));
    }

    #[test]
    fn relay_evidence_preserves_the_no_completion_caveat() {
        let log = r#"
{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
"#;
        let evidence = relay_evidence(log);
        assert!(evidence.passes("splice"));
        let rendered = evidence.to_json(Path::new("landing.log"), "splice").to_python_json();
        assert!(rendered.contains("\"perConnectionBackendEvidence\": \"not-emitted\""));
    }

    #[test]
    fn relay_evidence_rejects_missing_or_wrong_completion_backends() {
        let missing = relay_evidence(
            r#"{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
{"event":"connection_completed"}"#,
        );
        assert!(!missing.passes("splice"));
        let wrong = relay_evidence(
            r#"{"event":"relay_backend_report","backends":[{"backend":"splice","available":true}]}
{"event":"connection_accepted"}
{"event":"connection_closed"}
{"event":"connection_completed","relay_backend":"copy"}"#,
        );
        assert!(!wrong.passes("splice"));
    }
}
