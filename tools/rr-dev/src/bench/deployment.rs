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
    bench::{
        config::{self, RealityIdentity},
        evidence::{Publication, RunDirectory},
        host_lock::HostLock,
        identity::{self, Binary, Kind},
        process::Child,
        runner,
        soak,
        workspace::{self, Workspace},
    },
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
    pub(crate) asset_origin_port: Option<u16>,
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
    if let Some(port) = input.asset_origin_port {
        assets.insert(
            "geoip".to_owned(),
            string(format!("http://127.0.0.1:{port}/geoip.dat")),
        );
        assets.insert(
            "geosite".to_owned(),
            string(format!("http://127.0.0.1:{port}/geosite.dat")),
        );
    }
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

const ROUTING_GEOSITE_LABEL: &str = "proof";
const ROUTING_GEOSITE_DOMAIN: &str = "geo-proof.example";

pub(crate) fn write_routing_assets(directory: &Path) -> Result<(), String> {
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("could not create {}: {error}", directory.display()))?;
    std::fs::write(directory.join("geosite.dat"), geosite_fixture())
        .map_err(|error| format!("could not write geosite fixture: {error}"))?;
    std::fs::write(directory.join("geoip.dat"), geoip_fixture())
        .map_err(|error| format!("could not write geoip fixture: {error}"))
}

fn geosite_fixture() -> Vec<u8> {
    let mut domain = Vec::new();
    varint_field(&mut domain, 1, 3);
    bytes_field(&mut domain, 2, ROUTING_GEOSITE_DOMAIN.as_bytes());
    let mut site = Vec::new();
    bytes_field(&mut site, 1, ROUTING_GEOSITE_LABEL.as_bytes());
    bytes_field(&mut site, 2, &domain);
    let mut list = Vec::new();
    bytes_field(&mut list, 1, &site);
    list
}

fn geoip_fixture() -> Vec<u8> {
    let mut private = Vec::new();
    bytes_field(&mut private, 1, b"PRIVATE");
    for (address, prefix) in [([127, 0, 0, 0], 8), ([10, 0, 0, 0], 8)] {
        let mut cidr = Vec::new();
        bytes_field(&mut cidr, 1, &address);
        varint_field(&mut cidr, 2, prefix);
        bytes_field(&mut private, 2, &cidr);
    }
    let mut list = Vec::new();
    bytes_field(&mut list, 1, &private);
    list
}

fn bytes_field(output: &mut Vec<u8>, number: u8, value: &[u8]) {
    output.push((number << 3) | 2);
    encode_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

fn varint_field(output: &mut Vec<u8>, number: u8, value: u64) {
    output.push(number << 3);
    encode_varint(output, value);
}

fn encode_varint(output: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        output.push(u8::try_from(value & 0x7f).expect("seven bits fit in u8") | 0x80);
        value >>= 7;
    }
    output.push(u8::try_from(value).expect("final varint byte fits in u8"));
}

#[derive(Debug)]
pub(crate) struct RouteMatrixInput<'a> {
    pub(crate) uuids: &'a [String],
    pub(crate) socks_ports: &'a [u16],
    pub(crate) origin_a_port: u16,
    pub(crate) origin_b_port: u16,
    pub(crate) blocked_port: u16,
    pub(crate) sha_a: &'a str,
    pub(crate) sha_b: &'a str,
}

pub(crate) fn route_cases(input: &RouteMatrixInput<'_>) -> Result<Vec<RouteCase>, String> {
    if input.uuids.len() != 4 || input.socks_ports.len() != 4 {
        return Err("routing proof requires four UUIDs and four SOCKS ports".to_owned());
    }
    let mut cases = Vec::with_capacity(26);
    for index in 0..2 {
        for (label, host, port, expect) in [
            (
                "allow-domain-port-rule",
                "localhost",
                input.origin_a_port,
                RouteExpectation::Sha256(input.sha_a.to_owned()),
            ),
            (
                "allow-ip-port-rule",
                "127.0.0.1",
                input.origin_a_port,
                RouteExpectation::Sha256(input.sha_a.to_owned()),
            ),
            (
                "late-match-loopback-block",
                "127.0.0.1",
                input.origin_b_port,
                RouteExpectation::Blocked,
            ),
            (
                "global-port-block",
                "127.0.0.1",
                input.blocked_port,
                RouteExpectation::Blocked,
            ),
            (
                "global-domain-block",
                "blocked.example",
                80,
                RouteExpectation::Blocked,
            ),
            (
                "global-geosite-block",
                ROUTING_GEOSITE_DOMAIN,
                80,
                RouteExpectation::Blocked,
            ),
            (
                "group-default-block",
                "198.51.100.23",
                80,
                RouteExpectation::Blocked,
            ),
        ] {
            cases.push(route_case(input, index, "alpha", label, host, port, expect));
        }
    }
    for index in 2..4 {
        for (label, host, port, expect) in [
            (
                "default-via-socks-b",
                "8.8.8.8",
                80,
                RouteExpectation::Sha256(input.sha_b.to_owned()),
            ),
            (
                "group-geoip-private-block-loopback",
                "127.0.0.1",
                input.origin_b_port,
                RouteExpectation::Blocked,
            ),
            (
                "group-geoip-private-block-rfc1918",
                "10.255.255.1",
                input.origin_a_port,
                RouteExpectation::Blocked,
            ),
            (
                "global-domain-block",
                "blocked.example",
                80,
                RouteExpectation::Blocked,
            ),
            (
                "global-geosite-block",
                ROUTING_GEOSITE_DOMAIN,
                80,
                RouteExpectation::Blocked,
            ),
            (
                "global-port-block",
                "8.8.8.8",
                input.blocked_port,
                RouteExpectation::Blocked,
            ),
        ] {
            cases.push(route_case(input, index, "beta", label, host, port, expect));
        }
    }
    Ok(cases)
}

fn route_case(
    input: &RouteMatrixInput<'_>,
    index: usize,
    group: &str,
    label: &str,
    host: &str,
    port: u16,
    expect: RouteExpectation,
) -> RouteCase {
    RouteCase {
        uuid: input.uuids[index].clone(),
        group: group.to_owned(),
        label: label.to_owned(),
        socks_port: input.socks_ports[index],
        host: host.to_owned(),
        port,
        path: "/payload-1.bin".to_owned(),
        expect,
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RunPlan {
    pub(crate) repo: PathBuf,
    pub(crate) rust_bin: PathBuf,
    pub(crate) xray_bin: PathBuf,
    pub(crate) out_dir: PathBuf,
    pub(crate) run_id: String,
    pub(crate) program: Plan,
    pub(crate) keep_work: bool,
}

#[derive(Debug)]
pub(crate) struct RunOutcome {
    pub(crate) summary_path: PathBuf,
    pub(crate) marker_path: PathBuf,
}

struct RunState<'a> {
    plan: &'a RunPlan,
    rust: Binary,
    xray: Binary,
    run: RunDirectory,
    workspace: Workspace,
    lock: HostLock,
    children: Vec<Child>,
    next_port: u16,
    port_limit: u16,
}

struct SharedFixture {
    route_origin_port: u16,
    fixed_origin_port: u16,
    cover_port: u16,
    payload_a: PathBuf,
    payload_b: PathBuf,
    sha_a: String,
    sha_b: String,
}

impl RunState<'_> {
    fn port(&mut self) -> Result<u16, String> {
        if self.next_port >= self.port_limit {
            return Err("deployment runtime exhausted its reserved port block".to_owned());
        }
        let port = self.next_port;
        self.next_port += 1;
        Ok(port)
    }

    fn spawn_helper(
        &mut self,
        label: &str,
        args: &[String],
        log_name: &str,
        port: u16,
    ) -> Result<(), String> {
        let executable = std::env::current_exe()
            .map_err(|error| format!("could not identify rr-dev executable: {error}"))?;
        let mut child = Child::spawn_isolated(
            label,
            &executable,
            args,
            self.workspace.path(),
            &isolated_environment(),
            &self.workspace.join(log_name),
        )
        .map_err(|error| error.to_string())?;
        child
            .wait_for_port(port, Duration::from_secs(30))
            .map_err(|error| error.to_string())?;
        self.children.push(child);
        Ok(())
    }

    fn spawn_origin(
        &mut self,
        label: &str,
        directory: &Path,
        port: u16,
        tls: Option<(&Path, &Path)>,
    ) -> Result<(), String> {
        let mut args = vec![
            "bench".to_owned(),
            "origin".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--payload-dir".to_owned(),
            directory.display().to_string(),
            "--put-log".to_owned(),
            self.workspace
                .join(&format!("{label}-put.jsonl"))
                .display()
                .to_string(),
            "--label".to_owned(),
            label.to_owned(),
        ];
        if let Some((certificate, key)) = tls {
            args.extend([
                "--tls-cert".to_owned(),
                certificate.display().to_string(),
                "--tls-key".to_owned(),
                key.display().to_string(),
            ]);
        }
        self.spawn_helper(label, &args, &format!("{label}.log"), port)
    }

    fn spawn_xray_client(
        &mut self,
        label: &str,
        server_port: u16,
        socks_port: u16,
        public_key: &str,
        identity: &RealityIdentity,
    ) -> Result<(), String> {
        let path = self.workspace.join(&format!("{label}.json"));
        soak::write_config(
            &path,
            &config::xray_client(
                identity,
                server_port,
                socks_port,
                public_key,
            )
            .to_python_json(),
        )?;
        let child = soak::spawn_xray_client(
            label,
            &self.xray,
            &path,
            &self.workspace,
            &self.workspace.join(&format!("{label}.log")),
            socks_port,
        )?;
        self.children.push(child);
        Ok(())
    }
}

pub(crate) fn run_routing_acceptance(plan: &RunPlan) -> Result<RunOutcome, String> {
    plan.program.validate()?;
    if plan.run_id.trim().is_empty() {
        return Err("deployment run ID must not be empty".to_owned());
    }
    if !plan.program.sections.contains(&Section::Routing) {
        return Err("deployment routing acceptance requires the routing section".to_owned());
    }
    let rust = identity::register("rust-reality", &plan.rust_bin, "", Kind::Rust)?;
    let xray = identity::register("xray", &plan.xray_bin, "", Kind::Xray)?;
    let lock = HostLock::acquire(&runner::default_lock_path())?;
    let mut workspace = Workspace::create("deployment")?;
    if plan.keep_work {
        workspace.keep();
    }
    let run = RunDirectory::create(&plan.out_dir)?;
    let base_port = workspace::reserve_block(96)?;
    let mut state = RunState {
        plan,
        rust,
        xray,
        run,
        workspace,
        lock,
        children: Vec::new(),
        next_port: base_port,
        port_limit: base_port + 96,
    };
    state
        .run
        .write_new("plan.json", &plan.program.to_json().to_python_json())?;
    write_environment(&state)?;
    let fixture = prepare_shared_fixture(&mut state)?;
    run_routing_section(&mut state, &fixture)?;
    run_cost_section(&mut state, &fixture)?;
    run_topology_section(&mut state, &fixture)?;
    let summary = routing_run_summary(&state)?;
    let summary_path = state.run.write_new("summary.json", &summary.to_python_json())?;
    let contract = run_contract(&state, &summary_path)?;
    let marker_path = state.run.publish(
        Publication::Contract,
        &contract.to_python_json(),
        &plan.run_id,
        "benchmark-deployment",
    )?;
    Ok(RunOutcome {
        summary_path,
        marker_path,
    })
}

#[derive(Clone, Copy)]
struct CostVariant {
    label: &'static str,
    uuids: usize,
    rules: usize,
    global_rules: usize,
    strategy: &'static str,
    domain_destination: bool,
    with_ip: bool,
}

const COST_VARIANTS: [CostVariant; 5] = [
    CostVariant {
        label: "simple",
        uuids: 1,
        rules: 0,
        global_rules: 0,
        strategy: "AsIs",
        domain_destination: false,
        with_ip: false,
    },
    CostVariant {
        label: "medium",
        uuids: 100,
        rules: 16,
        global_rules: 4,
        strategy: "AsIs",
        domain_destination: false,
        with_ip: true,
    },
    CostVariant {
        label: "complex",
        uuids: 1_000,
        rules: 64,
        global_rules: 8,
        strategy: "AsIs",
        domain_destination: false,
        with_ip: true,
    },
    CostVariant {
        label: "complex-ipifnonmatch",
        uuids: 1_000,
        rules: 64,
        global_rules: 8,
        strategy: "IPIfNonMatch",
        domain_destination: true,
        with_ip: true,
    },
    CostVariant {
        label: "complex-ipondemand",
        uuids: 1_000,
        rules: 64,
        global_rules: 8,
        strategy: "IPOnDemand",
        domain_destination: true,
        with_ip: true,
    },
];

fn run_cost_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    for variant in COST_VARIANTS {
        let server_port = state.port()?;
        let socks_port = state.port()?;
        let uuids = generate_uuids(&state.rust, variant.uuids)?;
        let generated = soak::generated_public_config(
            &state.rust.path,
            vec![
                "config".to_owned(),
                "generate".to_owned(),
                "standalone".to_owned(),
                "--listen".to_owned(),
                "127.0.0.1".to_owned(),
                "--port".to_owned(),
                server_port.to_string(),
                "--target".to_owned(),
                format!("127.0.0.1:{}", fixture.cover_port),
                "--server-name".to_owned(),
                "localhost".to_owned(),
            ],
            &state.workspace,
            &format!("assets-cost-{}", variant.label),
        )?;
        let json = scale_config(&ScaleConfigInput {
            base: &generated.json,
            uuids: &uuids,
            rules: variant.rules,
            global_rules: variant.global_rules,
            with_ip: variant.with_ip,
            strategy: variant.strategy,
            assets: &state.workspace.join(&format!("assets-cost-{}", variant.label)),
        })?;
        let config_path = state.workspace.join(&format!("cost-{}.json", variant.label));
        soak::write_config(&config_path, &json)?;
        soak::check_config(&state.rust.path, &config_path)?;
        let server = soak::spawn_rust(
            &format!("deployment-cost-{}-server", variant.label),
            &state.rust,
            &config_path,
            &state.workspace,
            &isolated_environment(),
            &state.workspace.join(&format!("cost-{}-server.log", variant.label)),
            server_port,
        )?;
        state.children.push(server);
        let identity = RealityIdentity {
            uuid: uuids[0].clone(),
            short_id: generated.short_id,
            server_name: "localhost".to_owned(),
            target: format!("127.0.0.1:{}", fixture.cover_port),
        };
        state.spawn_xray_client(
            &format!("deployment-cost-{}-client", variant.label),
            server_port,
            socks_port,
            &generated.public_key,
            &identity,
        )?;
        let destination = if variant.domain_destination {
            super::workload::Destination::Domain("localhost".to_owned())
        } else {
            super::workload::Destination::Loopback
        };
        if super::workload::connect_through(
            socks_port,
            &destination,
            fixture.route_origin_port,
        )
        .is_none()
        {
            return Err(format!(
                "deployment cost {} warm-up did not reach the native origin",
                variant.label
            ));
        }
        let rows = super::workload::run_slot_to(
            &super::workload::SetupRatePlan {
                socks_port,
                origin_port: fixture.route_origin_port,
                connections: state.plan.program.connections,
                concurrencies: state.plan.program.concurrencies.clone(),
                samples: state.plan.program.samples,
                implementation: format!("cost-{}", variant.label),
                block: 0,
                position: 0,
                record_latencies: false,
            },
            &destination,
        )?;
        state.run.write_jsonl(
            &format!("setup-cost-{}.jsonl", variant.label),
            &rows.iter().map(setup_row_json).collect::<Vec<_>>(),
        )?;
    }
    Ok(())
}

fn setup_row_json(row: &super::workload::SampleRow) -> String {
    let mut fields = vec![
        ("concurrency", count(row.concurrency)),
        ("sampleIndex", count(row.sample_index)),
        ("wallSeconds", Json::Float(row.wall_seconds)),
        ("connections", count(row.connections)),
        ("failed", count(row.failed)),
    ];
    if let Some(rate) = row.connections_per_second() {
        fields.push(("connectionsPerSecond", Json::Float(rate)));
        for (name, fraction) in [
            ("p50Seconds", 0.50),
            ("p90Seconds", 0.90),
            ("p95Seconds", 0.95),
            ("p99Seconds", 0.99),
        ] {
            if let Ok(value) = super::aggregate::floor_percentile(&row.latencies_seconds, fraction) {
                fields.push((name, Json::Float(value)));
            }
        }
    }
    Json::object(fields).to_compact_json()
}

#[derive(Clone, Copy)]
struct Topology {
    label: &'static str,
    socks_port: u16,
}

#[expect(
    clippy::too_many_lines,
    reason = "the four reviewed topologies are materialized together for direct comparison"
)]
fn run_topology_section(state: &mut RunState<'_>, fixture: &SharedFixture) -> Result<(), String> {
    let upstream_socks = state.port()?;
    state.spawn_helper(
        "deployment-transparent-socks",
        &[
            "bench".to_owned(),
            "socks-server".to_owned(),
            "--port".to_owned(),
            upstream_socks.to_string(),
        ],
        "transparent-socks.log",
        upstream_socks,
    )?;

    let standalone_port = state.port()?;
    let standalone_socks = state.port()?;
    let standalone = deployment_public_config(
        state,
        "standalone",
        vec![
            "config".to_owned(),
            "generate".to_owned(),
            "standalone".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            standalone_port.to_string(),
            "--target".to_owned(),
            format!("127.0.0.1:{}", fixture.cover_port),
            "--server-name".to_owned(),
            "localhost".to_owned(),
        ],
    )?;
    spawn_generated_rust(state, "topo-a", standalone_port, &standalone.json)?;
    let standalone_identity = identity_for(&standalone, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-topo-a-client",
        standalone_port,
        standalone_socks,
        &standalone.public_key,
        &standalone_identity,
    )?;

    let nxr_key = soak::node_key(&state.rust.path)?;
    let nxr_line_port = state.port()?;
    let nxr_landing_port = state.port()?;
    let nxr_socks = state.port()?;
    let nxr_line = deployment_public_config(
        state,
        "nxr-line",
        line_generation_args(
            nxr_line_port,
            fixture.cover_port,
            nxr_landing_port,
            &nxr_key,
        ),
    )?;
    let nxr_landing = landing_config(state, "nxr-landing", nxr_landing_port, &nxr_key, "warn")?;
    spawn_generated_rust(state, "topo-b-landing", nxr_landing_port, &nxr_landing)?;
    spawn_generated_rust(state, "topo-b-line", nxr_line_port, &nxr_line.json)?;
    let nxr_identity = identity_for(&nxr_line, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-topo-b-client",
        nxr_line_port,
        nxr_socks,
        &nxr_line.public_key,
        &nxr_identity,
    )?;

    let socks_line_port = state.port()?;
    let socks_client_port = state.port()?;
    let socks_line = deployment_public_config(
        state,
        "socks-line",
        line_generation_args(socks_line_port, fixture.cover_port, 9, &nxr_key),
    )?;
    let socks_json = soak::patch_socks_outbound(&socks_line.json, upstream_socks)?;
    spawn_generated_rust(state, "topo-c-line", socks_line_port, &socks_json)?;
    let socks_identity = identity_for(&socks_line, fixture.cover_port);
    state.spawn_xray_client(
        "deployment-topo-c-client",
        socks_line_port,
        socks_client_port,
        &socks_line.public_key,
        &socks_identity,
    )?;

    let xray_server_port = state.port()?;
    let xray_client_port = state.port()?;
    let keys = suites::generate_xray_keys(&state.xray.path)?;
    let xray_uuid = generate_uuids(&state.rust, 1)?
        .pop()
        .ok_or_else(|| "rust-reality uuid returned no comparator UUID".to_owned())?;
    let xray_identity = RealityIdentity {
        uuid: xray_uuid,
        short_id: "0123456789abcdef".to_owned(),
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{}", fixture.cover_port),
    };
    let xray_server_config = state.workspace.join("topo-d-xray-server.json");
    soak::write_config(
        &xray_server_config,
        &config::xray_server_with_socks(
            &xray_identity,
            xray_server_port,
            &keys.private,
            upstream_socks,
        )
        .to_python_json(),
    )?;
    let mut xray_server = Child::spawn_isolated(
        "deployment-topo-d-server",
        &state.xray.path,
        &[
            "run".to_owned(),
            "-config".to_owned(),
            xray_server_config.display().to_string(),
        ],
        state.workspace.path(),
        &isolated_environment(),
        &state.workspace.join("topo-d-xray-server.log"),
    )
    .map_err(|error| error.to_string())?;
    xray_server
        .wait_for_port(xray_server_port, Duration::from_secs(30))
        .map_err(|error| error.to_string())?;
    state.children.push(xray_server);
    state.spawn_xray_client(
        "deployment-topo-d-client",
        xray_server_port,
        xray_client_port,
        &keys.public,
        &xray_identity,
    )?;

    let topologies = [
        Topology {
            label: "topo-a",
            socks_port: standalone_socks,
        },
        Topology {
            label: "topo-b",
            socks_port: nxr_socks,
        },
        Topology {
            label: "topo-c",
            socks_port: socks_client_port,
        },
        Topology {
            label: "topo-d",
            socks_port: xray_client_port,
        },
    ];
    for topology in topologies {
        run_topology_setup(state, fixture, topology)?;
        for cell in &state.plan.program.throughput_cells {
            run_topology_throughput(state, fixture, topology, *cell)?;
        }
    }
    Ok(())
}

fn deployment_public_config(
    state: &RunState<'_>,
    label: &str,
    args: Vec<String>,
) -> Result<soak::GeneratedPublicConfig, String> {
    let mut generated = soak::generated_public_config(
        &state.rust.path,
        args,
        &state.workspace,
        &format!("assets-{label}"),
    )?;
    generated.json = suites::set_rust_log_level(&generated.json, "warn")?;
    Ok(generated)
}

fn line_generation_args(
    line_port: u16,
    cover_port: u16,
    landing_port: u16,
    key: &str,
) -> Vec<String> {
    vec![
        "config".to_owned(),
        "generate".to_owned(),
        "line".to_owned(),
        "--listen".to_owned(),
        "127.0.0.1".to_owned(),
        "--port".to_owned(),
        line_port.to_string(),
        "--target".to_owned(),
        format!("127.0.0.1:{cover_port}"),
        "--server-name".to_owned(),
        "localhost".to_owned(),
        "--nxr-address".to_owned(),
        "127.0.0.1".to_owned(),
        "--nxr-port".to_owned(),
        landing_port.to_string(),
        "--nxr-key".to_owned(),
        key.to_owned(),
    ]
}

fn landing_config(
    state: &RunState<'_>,
    label: &str,
    port: u16,
    key: &str,
    level: &str,
) -> Result<String, String> {
    let outcome = Tool::new(state.rust.path.display().to_string())
        .args([
            "config".to_owned(),
            "generate".to_owned(),
            "landing".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            port.to_string(),
            "--nxr-key".to_owned(),
            key.to_owned(),
        ])
        .probe()
        .map_err(|error| format!("{label} config generation failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "{label} config generation exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let patched = soak::patch_server_config(
        outcome.trimmed_stdout(),
        &state.workspace,
        &format!("assets-{label}"),
        false,
    )?;
    suites::set_rust_log_level(&patched, level)
}

fn spawn_generated_rust(
    state: &mut RunState<'_>,
    label: &str,
    port: u16,
    json: &str,
) -> Result<PathBuf, String> {
    let path = state.workspace.join(&format!("{label}.json"));
    soak::write_config(&path, json)?;
    soak::check_config(&state.rust.path, &path)?;
    let child = soak::spawn_rust(
        &format!("deployment-{label}"),
        &state.rust,
        &path,
        &state.workspace,
        &isolated_environment(),
        &state.workspace.join(&format!("{label}.log")),
        port,
    )?;
    state.children.push(child);
    Ok(path)
}

fn identity_for(generated: &soak::GeneratedPublicConfig, cover_port: u16) -> RealityIdentity {
    RealityIdentity {
        uuid: generated.uuid.clone(),
        short_id: generated.short_id.clone(),
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{cover_port}"),
    }
}

fn run_topology_setup(
    state: &RunState<'_>,
    fixture: &SharedFixture,
    topology: Topology,
) -> Result<(), String> {
    let destination = super::workload::Destination::Loopback;
    if super::workload::connect_through(
        topology.socks_port,
        &destination,
        fixture.route_origin_port,
    )
    .is_none()
    {
        return Err(format!(
            "{} warm-up did not reach the native origin",
            topology.label
        ));
    }
    let rows = super::workload::run_slot(&super::workload::SetupRatePlan {
        socks_port: topology.socks_port,
        origin_port: fixture.route_origin_port,
        connections: state.plan.program.connections,
        concurrencies: state.plan.program.concurrencies.clone(),
        samples: state.plan.program.samples,
        implementation: topology.label.to_owned(),
        block: 0,
        position: 0,
        record_latencies: false,
    })?;
    state.run.write_jsonl(
        &format!("setup-{}.jsonl", topology.label),
        &rows.iter().map(setup_row_json).collect::<Vec<_>>(),
    )?;
    Ok(())
}

fn run_topology_throughput(
    state: &RunState<'_>,
    fixture: &SharedFixture,
    topology: Topology,
    cell: ThroughputCell,
) -> Result<(), String> {
    let payload = fixture
        .payload_a
        .join(format!("payload-{}.bin", cell.payload_mib));
    let rows = run_socks_throughput(&SocksThroughputPlan {
        label: topology.label.to_owned(),
        socks_port: topology.socks_port,
        url: format!(
            "http://127.0.0.1:{}/payload-{}.bin",
            fixture.route_origin_port, cell.payload_mib
        ),
        payload_mib: cell.payload_mib,
        samples: state.plan.program.throughput_samples,
        concurrencies: vec![cell.concurrency],
        expected_sha256: hash::sha256_file(&payload)?,
        workspace: state.workspace.path().to_path_buf(),
    })?;
    state.run.write_jsonl(
        &format!(
            "tput-{}-{}mib-c{}.jsonl",
            topology.label, cell.payload_mib, cell.concurrency
        ),
        &rows
            .iter()
            .map(|row| row.to_json().to_compact_json())
            .collect::<Vec<_>>(),
    )?;
    Ok(())
}

fn prepare_shared_fixture(state: &mut RunState<'_>) -> Result<SharedFixture, String> {
    let route_origin_port = state.port()?;
    let fixed_origin_port = state.port()?;
    let cover_port = state.port()?;
    let payload_a = state.workspace.join("payload-a");
    let payload_b = state.workspace.join("payload-b");
    std::fs::create_dir_all(&payload_a)
        .map_err(|error| format!("could not create {}: {error}", payload_a.display()))?;
    std::fs::create_dir_all(&payload_b)
        .map_err(|error| format!("could not create {}: {error}", payload_b.display()))?;
    super::origin_go::write_setup_payload(&payload_a)?;
    super::origin::write_payload(&payload_a.join("payload-0.bin"), 256)?;
    let mut sizes = BTreeSet::from([1_u64, state.plan.program.longflow_mib]);
    sizes.extend(
        state
            .plan
            .program
            .throughput_cells
            .iter()
            .map(|cell| cell.payload_mib),
    );
    for mebibytes in sizes {
        super::origin::write_payload(
            &payload_a.join(format!("payload-{mebibytes}.bin")),
            mebibytes * 1024 * 1024,
        )?;
    }
    write_inverted_payload(&payload_b.join("payload-1.bin"), 1024 * 1024)?;
    write_routing_assets(&payload_a)?;
    let sha_a = hash::sha256_file(&payload_a.join("payload-1.bin"))?;
    let sha_b = hash::sha256_file(&payload_b.join("payload-1.bin"))?;
    let (certificate, key) = super::origin_tls::generate_self_signed(state.workspace.path())?;
    state.spawn_origin("deployment-origin-a", &payload_a, route_origin_port, None)?;
    state.spawn_origin("deployment-origin-b", &payload_b, fixed_origin_port, None)?;
    state.spawn_origin(
        "deployment-cover",
        &payload_a,
        cover_port,
        Some((&certificate, &key)),
    )?;
    Ok(SharedFixture {
        route_origin_port,
        fixed_origin_port,
        cover_port,
        payload_a,
        payload_b,
        sha_a,
        sha_b,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "one bounded section keeps process ownership and its proof visibly together"
)]
fn run_routing_section(
    state: &mut RunState<'_>,
    fixture: &SharedFixture,
) -> Result<(), String> {
    let fixed_socks_port = state.port()?;
    let server_port = state.port()?;
    let socks_ports = [state.port()?, state.port()?, state.port()?, state.port()?];
    state.spawn_helper(
        "deployment-fixed-socks",
        &[
            "bench".to_owned(),
            "socks-server".to_owned(),
            "--port".to_owned(),
            fixed_socks_port.to_string(),
            "--fixed-target".to_owned(),
            format!("127.0.0.1:{}", fixture.fixed_origin_port),
        ],
        "fixed-socks.log",
        fixed_socks_port,
    )?;
    let uuids = generate_uuids(&state.rust, 4)?;
    let generated = soak::generated_public_config(
        &state.rust.path,
        vec![
            "config".to_owned(),
            "generate".to_owned(),
            "standalone".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1".to_owned(),
            "--port".to_owned(),
            server_port.to_string(),
            "--target".to_owned(),
            format!("127.0.0.1:{}", fixture.cover_port),
            "--server-name".to_owned(),
            "localhost".to_owned(),
        ],
        &state.workspace,
        "assets-routing-base",
    )?;
    let routing = routing_config(&RoutingConfigInput {
        base: &generated.json,
        uuids: &uuids,
        origin_a_port: fixture.route_origin_port,
        socks_b_port: fixed_socks_port,
        blocked_port: 9666,
        geosite_label: ROUTING_GEOSITE_LABEL,
        assets: &state.workspace.join("assets-routing"),
        asset_origin_port: Some(fixture.route_origin_port),
    })?;
    let server_config = state.workspace.join("routing-server.json");
    soak::write_config(&server_config, &routing.json)?;
    soak::check_config(&state.rust.path, &server_config)?;
    let server = soak::spawn_rust(
        "deployment-routing-server",
        &state.rust,
        &server_config,
        &state.workspace,
        &isolated_environment(),
        &state.workspace.join("routing-server.log"),
        server_port,
    )?;
    state.children.push(server);
    for index in 0..4 {
        let identity = RealityIdentity {
            uuid: uuids[index].clone(),
            short_id: routing.short_ids[index].clone(),
            server_name: "localhost".to_owned(),
            target: format!("127.0.0.1:{}", fixture.cover_port),
        };
        state.spawn_xray_client(
            &format!("deployment-routing-client-{index}"),
            server_port,
            socks_ports[index],
            &generated.public_key,
            &identity,
        )?;
    }
    let cases = route_cases(&RouteMatrixInput {
        uuids: &uuids,
        socks_ports: &socks_ports,
        origin_a_port: fixture.route_origin_port,
        origin_b_port: fixture.fixed_origin_port,
        blocked_port: 9666,
        sha_a: &fixture.sha_a,
        sha_b: &fixture.sha_b,
    })?;
    let results = probe_routes(&cases);
    state.run.write_jsonl(
        "routing-correctness.jsonl",
        &results
            .iter()
            .map(|result| result.to_json().to_compact_json())
            .collect::<Vec<_>>(),
    )?;
    let summary = routing_summary(&results);
    state
        .run
        .write_new("summary-routing.json", &summary.to_python_json())?;
    if results.iter().all(|result| result.passed) {
        Ok(())
    } else {
        Err(format!(
            "deployment routing correctness failed {}/{} cases",
            results.iter().filter(|result| !result.passed).count(),
            results.len()
        ))
    }
}

fn generate_uuids(binary: &Binary, count: usize) -> Result<Vec<String>, String> {
    let outcome = Tool::new(binary.path.display().to_string())
        .args(["uuid".to_owned(), count.to_string()])
        .probe()
        .map_err(|error| format!("rust-reality uuid failed: {error}"))?;
    if !outcome.success() {
        return Err(format!(
            "rust-reality uuid exited {:?}: {}",
            outcome.code,
            outcome.stderr.trim_end()
        ));
    }
    let values = outcome
        .trimmed_stdout()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.len() != count {
        return Err(format!(
            "rust-reality uuid returned {} values, expected {count}",
            values.len()
        ));
    }
    Ok(values)
}

fn write_inverted_payload(path: &Path, size: u64) -> Result<(), String> {
    let chunk: Vec<u8> = (0_u8..=255)
        .rev()
        .cycle()
        .take(256 * 4096)
        .collect();
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    let mut remaining = size;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
        file.write_all(&chunk[..take])
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        remaining -= take as u64;
    }
    Ok(())
}

fn write_environment(state: &RunState<'_>) -> Result<(), String> {
    let commit = Tool::new("git")
        .args([
            "-C".to_owned(),
            state.plan.repo.display().to_string(),
            "rev-parse".to_owned(),
            "HEAD".to_owned(),
        ])
        .probe()
        .map_err(|error| format!("could not identify harness commit: {error}"))?;
    if !commit.success() {
        return Err(format!(
            "could not identify harness commit: {}",
            commit.stderr.trim_end()
        ));
    }
    let environment = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("runId", Json::string(&state.plan.run_id)),
        ("harnessCommit", Json::string(commit.trimmed_stdout())),
        ("rustRealityBin", Json::string(state.rust.path.display().to_string())),
        ("rustRealitySha256", Json::string(&state.rust.sha256)),
        ("rustRealityIdentity", Json::string(&state.rust.identity)),
        ("xrayBin", Json::string(state.xray.path.display().to_string())),
        ("xraySha256", Json::string(&state.xray.sha256)),
        ("xrayIdentity", Json::string(&state.xray.identity)),
        ("hostLock", Json::string(state.lock.device_inode())),
    ]);
    state
        .run
        .write_new("environment.json", &environment.to_python_json())?;
    Ok(())
}

fn routing_run_summary(state: &RunState<'_>) -> Result<Json, String> {
    let raw = std::fs::read_to_string(state.run.join("summary-routing.json"))
        .map_err(|error| format!("could not read routing summary: {error}"))?;
    let routing = json_in::parse(&raw)
        .map_err(|error| format!("routing summary is invalid JSON: {error}"))?;
    let verdict = routing
        .str_field("routing", "verdict")
        .map_err(|error| error.to_string())?;
    Ok(Json::object([
        ("schemaVersion", Json::Int(1)),
        ("status", Json::string("COMPLETE")),
        ("program", state.plan.program.to_json()),
        ("completedSections", Json::Array(vec![Json::string("routing")])),
        ("routingCorrectness", parsed_to_json(&routing)?),
        ("dataQualityVerdict", Json::string(verdict)),
        ("correctnessVerdict", Json::string(verdict)),
        ("performanceVerdict", Json::string("NOT_EVALUATED")),
        ("gateVerdict", Json::string(verdict)),
        ("overallVerdict", Json::string("NOT_EVALUATED")),
    ]))
}

fn run_contract(state: &RunState<'_>, summary: &Path) -> Result<Json, String> {
    Ok(Json::object([
        ("schemaVersion", Json::Int(1)),
        ("phase", Json::string("complete")),
        ("suite", Json::string("benchmark-deployment")),
        ("runId", Json::string(&state.plan.run_id)),
        ("plan", state.plan.program.to_json()),
        (
            "summary",
            Json::object([
                ("path", Json::string(summary.display().to_string())),
                ("sha256", Json::string(hash::sha256_file(summary)?)),
            ]),
        ),
    ]))
}

fn parsed_to_json(value: &Value) -> Result<Json, String> {
    match value {
        Value::Null => Ok(Json::Null),
        Value::Bool(value) => Ok(Json::Bool(*value)),
        Value::Number(value) => value
            .parse::<i64>()
            .map(Json::Int)
            .or_else(|_| value.parse::<f64>().map(Json::Float))
            .map_err(|error| format!("could not convert JSON number {value}: {error}")),
        Value::Str(value) => Ok(Json::string(value)),
        Value::Array(values) => values
            .iter()
            .map(parsed_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Json::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), parsed_to_json(value)?)))
            .collect::<Result<Vec<_>, String>>()
            .map(Json::object),
    }
}

fn isolated_environment() -> Vec<(String, String)> {
    vec![(
        "PATH".to_owned(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
    )]
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
            asset_origin_port: Some(8090),
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
        assert_eq!(
            value
                .field("", "assets")
                .unwrap()
                .str_field("assets", "geosite")
                .unwrap(),
            "http://127.0.0.1:8090/geosite.dat"
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
    fn routing_assets_and_case_matrix_are_bounded_and_complete() {
        let root = std::env::temp_dir().join(format!(
            "rr-deployment-routing-assets-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        write_routing_assets(&root).unwrap();
        assert!(!std::fs::read(root.join("geosite.dat")).unwrap().is_empty());
        assert!(!std::fs::read(root.join("geoip.dat")).unwrap().is_empty());
        let uuids = uuids(4);
        let cases = route_cases(&RouteMatrixInput {
            uuids: &uuids,
            socks_ports: &[1001, 1002, 1003, 1004],
            origin_a_port: 8080,
            origin_b_port: 8081,
            blocked_port: 9666,
            sha_a: "a",
            sha_b: "b",
        })
        .unwrap();
        assert_eq!(cases.len(), 26);
        assert_eq!(cases.iter().filter(|case| case.group == "alpha").count(), 14);
        assert_eq!(cases.iter().filter(|case| case.group == "beta").count(), 12);
        assert_eq!(
            cases
                .iter()
                .filter(|case| matches!(case.expect, RouteExpectation::Sha256(_)))
                .count(),
            6
        );
        std::fs::remove_dir_all(root).unwrap();
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
