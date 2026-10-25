//! Routing correctness section helpers for the deployment characterization suite.
//!
//! Owns the reviewed routing policy JSON builders, geosite/geoip fixtures, the
//! four-user route-case matrix, and the live routing-correctness section runner.
//! Plan dimensions stay in [`super::deployment_plan`]; probe execution helpers
//! stay in [`super::deployment_probe`]. Process lifecycle still rides on
//! [`super::deployment::RunState`].

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use crate::{
    bench::{config::RealityIdentity, soak},
    hash,
    perf::json_in::Value,
};

use super::deployment::{RunState, SharedFixture, generate_uuids, isolated_environment};
use super::deployment_json::{
    first_client, number, object, replace_clients, root_object, string, strings,
};
use super::deployment_probe::{RouteCase, RouteExpectation, probe_routes, routing_summary};
use super::suites;

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
                ("settings", object([("responseDelayMs", number(0))])),
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
                        [(
                            "domain",
                            strings([format!("geosite:{}", input.geosite_label)]),
                        )],
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
    // Asset loading is download-first with cache fallback. A closed local HTTPS
    // port makes that fallback deterministic and keeps the routing proof off the
    // public network while satisfying production's HTTPS-only source policy.
    assets.insert("requestTimeoutSeconds".to_owned(), number(1));
    assets.insert("geoip".to_owned(), string("https://127.0.0.1:9/geoip.dat"));
    assets.insert(
        "geosite".to_owned(),
        string("https://127.0.0.1:9/geosite.dat"),
    );
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
        return Err(format!(
            "unknown routing domain strategy: {}",
            input.strategy
        ));
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
        (
            "rules",
            Value::Array(scale_rules(input.rules, input.with_ip, "")),
        ),
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
                    .map(|salt| {
                        hash::sha256_hex(format!("{uuid}:{salt}").as_bytes())[..16].to_owned()
                    })
                    .find(|candidate| !used.contains(&candidate.to_ascii_lowercase()))
                    .ok_or_else(|| {
                        "could not derive a unique short ID for VLESS client".to_owned()
                    })?;
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
                0 => (
                    "full",
                    "domain",
                    format!("full:host{index}.scale-example.test"),
                ),
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
    rule.extend(
        fields
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value)),
    );
    Value::Object(rule)
}

pub(crate) const ROUTING_GEOSITE_LABEL: &str = "proof";
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

pub(crate) fn run_routing_section(
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
        &soak::PublicNodeSpec::standalone(
            server_port,
            &format!("127.0.0.1:{}", fixture.cover_port),
        ),
        &state.workspace,
        "assets-routing-base",
    )?;
    let routing_assets = state.workspace.join("assets-routing");
    write_routing_assets(&routing_assets)?;
    let routing = routing_config(&RoutingConfigInput {
        base: &generated.json,
        uuids: &uuids,
        origin_a_port: fixture.route_origin_port,
        socks_b_port: fixed_socks_port,
        blocked_port: 9666,
        geosite_label: ROUTING_GEOSITE_LABEL,
        assets: &routing_assets,
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
