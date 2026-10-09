//! Offline proof of the fixed guest fault actions and installed network faults.
#![allow(missing_docs)]

use serde::Deserialize;

use super::schema::{Cell, Contract, Fault, Role};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    argv: Vec<String>,
    started_unix_ms: u64,
    completed_unix_ms: u64,
    exit_code: Option<i32>,
    stdout: Option<String>,
    stderr: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub role: String,
    pub boot_id: String,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub name: String,
    pub begin: bool,
    pub commands: Vec<Command>,
    #[serde(deserialize_with = "required_option")]
    pub error: Option<String>,
    pub configuration_sha256: String,
    pub warm_tcp: Option<bool>,
    #[serde(deserialize_with = "required_option")]
    pub termination_signal: Option<i32>,
}

fn required_option<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::deserialize(deserializer)
}

pub fn parse(bytes: &[u8]) -> Result<Action, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

#[derive(Deserialize)]
#[serde(tag = "kind")]
enum Qdisc {
    #[serde(rename = "netem")]
    Netem { root: bool, options: Netem },
    #[serde(rename = "fq_codel")]
    FqCodel,
    #[serde(rename = "pfifo_fast")]
    PfifoFast,
    #[serde(rename = "noqueue")]
    NoQueue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Netem {
    limit: u64,
    delay: Option<Timing>,
    #[serde(rename = "loss-random")]
    loss: Option<DropRate>,
    ecn: bool,
    gap: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Timing {
    delay: f64,
    jitter: f64,
    correlation: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DropRate {
    loss: f64,
    correlation: f64,
}

fn close(actual: f64, expected: f64) -> bool {
    actual.is_finite() && (actual - expected).abs() < 0.000_001
}

pub fn qdisc(text: &str, fault: Option<&str>) -> Result<(), String> {
    let rows: Vec<Qdisc> = serde_json::from_str(text).map_err(|error| error.to_string())?;
    if rows.is_empty() {
        return Err("missing qdisc observation".to_owned());
    }
    let mut netem = rows.into_iter().filter_map(|row| match row {
        Qdisc::Netem { root, options } => Some((root, options)),
        Qdisc::FqCodel | Qdisc::PfifoFast | Qdisc::NoQueue => None,
    });
    let Some(name) = fault else {
        return if netem.next().is_none() {
            Ok(())
        } else {
            Err("unexpected retained netem fault".to_owned())
        };
    };
    let (root, options) = netem.next().ok_or("netem was not installed")?;
    if !root || netem.next().is_some() || options.limit != 1000 || options.ecn || options.gap != 0 {
        return Err("unexpected netem topology or options".to_owned());
    }
    // iproute2 tc/q_netem.c emits JSON times in seconds and loss as a fraction:
    // https://github.com/iproute2/iproute2/blob/v6.1.0/tc/q_netem.c
    let (delay, loss) = match name {
        "line-a-partition" => (0.0, 1.0),
        "rtt-50" => (0.025, 0.0),
        "rtt-100" => (0.05, 0.0),
        "rtt-200" => (0.1, 0.0),
        "rtt-100-loss-1" => (0.05, 0.01),
        _ => return Err("unknown network fault".to_owned()),
    };
    let delay_ok = options.delay.as_ref().map_or(delay == 0.0, |value| {
        close(value.delay, delay) && close(value.jitter, 0.0) && close(value.correlation, 0.0)
    });
    let loss_ok = options.loss.as_ref().map_or(loss == 0.0, |value| {
        close(value.loss, loss) && close(value.correlation, 0.0)
    });
    if !delay_ok || !loss_ok {
        return Err("installed RTT/loss differs from the fixed matrix".to_owned());
    }
    Ok(())
}

fn command<'a>(value: &'a Command, argv: &[&str], action: &Action) -> Result<&'a str, String> {
    if value.argv != argv
        || value.exit_code != Some(0)
        || value.error.is_some()
        || value.stderr.as_deref() != Some("")
        || value.stdout.is_none()
        || value.started_unix_ms < action.started_unix_ms
        || value.completed_unix_ms < value.started_unix_ms
        || value.completed_unix_ms > action.completed_unix_ms
    {
        return Err("fault command, exit status or interval was substituted".to_owned());
    }
    Ok(value.stdout.as_deref().expect("checked output"))
}

fn network_commands(action: &Action) -> Result<(), String> {
    let interfaces: &[&str] = match (action.role.as_str(), action.name.as_str()) {
        ("line-b", "line-a-partition") => &[],
        ("landing", "line-a-partition") => &["data0"],
        ("landing", _) => &["data0", "data1"],
        _ => &["data0"],
    };
    if action.commands.len() != interfaces.len() * 3 {
        return Err("missing network fault observations".to_owned());
    }
    for (interface, commands) in interfaces.iter().zip(action.commands.chunks_exact(3)) {
        let show = ["tc", "-j", "qdisc", "show", "dev", interface];
        qdisc(
            command(&commands[0], &show, action)?,
            (!action.begin).then_some(action.name.as_str()),
        )?;
        let mut change = vec![
            "tc",
            "qdisc",
            if action.begin { "replace" } else { "del" },
            "dev",
            interface,
            "root",
        ];
        if action.begin {
            change.push("netem");
            match action.name.as_str() {
                "line-a-partition" => change.extend(["loss", "100%"]),
                "rtt-50" => change.extend(["delay", "25ms"]),
                "rtt-100" => change.extend(["delay", "50ms"]),
                "rtt-200" => change.extend(["delay", "100ms"]),
                "rtt-100-loss-1" => change.extend(["delay", "50ms", "loss", "1%"]),
                _ => return Err("unknown network fault".to_owned()),
            }
        }
        command(&commands[1], &change, action)?;
        qdisc(
            command(&commands[2], &show, action)?,
            action.begin.then_some(action.name.as_str()),
        )?;
    }
    Ok(())
}

pub fn verify(
    action: &Action,
    role: &Role,
    cell: &Cell,
    fault: &Fault,
    contract: &Contract,
) -> Result<(), String> {
    let scheduled = cell
        .started_unix_ms
        .checked_add(if action.begin {
            fault.started_ms
        } else {
            fault.restored_ms
        })
        .ok_or("fault epoch overflow")?;
    if action.name != fault.name
        || action.role != role.name
        || action.boot_id != role.process.boot_id
        || scheduled
            .checked_add(contract.clock_guard_ms())
            .is_none_or(|time| action.started_unix_ms < time)
        || action.completed_unix_ms < action.started_unix_ms
        || action
            .completed_unix_ms
            .checked_add(contract.clock_guard_ms())
            .zip(scheduled.checked_add(contract.checkpoint_tolerance_ms))
            .is_none_or(|(end, deadline)| end > deadline)
        || action.error.is_some()
        || !action
            .commands
            .windows(2)
            .all(|pair| pair[0].completed_unix_ms <= pair[1].started_unix_ms)
        || !super::evaluate::digest(&action.configuration_sha256, 64)
        || action.termination_signal
            != (action.name == "landing-restart" && action.begin && role.name == "landing")
                .then_some(9)
        || action.warm_tcp
            != (role.name != "landing").then_some(!(fault.name == "cold" && action.begin))
    {
        return Err(
            "fault action identity, configuration, outcome or fixed interval changed".to_owned(),
        );
    }
    if action.name.starts_with("rtt-") || action.name == "line-a-partition" {
        return network_commands(action);
    }
    if action.name == "stale" && action.begin && role.name == "landing" {
        if action.commands.len() != 1 {
            return Err("missing stale socket eviction".to_owned());
        }
        let output = command(
            &action.commands[0],
            &[
                "ss",
                "-K",
                "state",
                "established",
                "dst",
                "192.0.2.5",
                "(",
                "sport",
                "=",
                ":9443",
                ")",
            ],
            action,
        )?;
        if !output
            .lines()
            .skip(1)
            .any(|line| line.contains("192.0.2.5:") && line.contains(":9443"))
        {
            return Err("stale-pool action evicted no matching sockets".to_owned());
        }
    } else if action.name == "landing-restart" && action.begin && role.name == "line-a" {
        restart_ingress(action)?;
    } else if !action.commands.is_empty() {
        return Err("unexpected command outside the prescribed action".to_owned());
    }
    Ok(())
}

/// Hold LANDING abort so the co-scheduled LINE-A `ss` census can witness the live
/// ingress first. Begin fires on all guests at the same schedule instant; without
/// this delay the landing kill tears down `:9444` before LINE-A's census (~34ms)
/// completes. Must stay under `checkpoint_tolerance_ms` (2000).
pub(super) const RESTART_CENSUS_HOLD_MS: u64 = 500;

/// Read-only census for LINE-A's active loopback ingress (fixture listen port 9444).
/// LANDING listens on 9443; a 9443 filter on LINE-A can never witness the prefix flow.
pub(super) const RESTART_INGRESS_COMMAND: [&str; 11] = [
    "ss",
    "-Hnt",
    "state",
    "established",
    "src",
    "127.0.0.1",
    "(",
    "sport",
    "=",
    ":9444",
    ")",
];

/// Record the single active prefix connection before its injected peer restart.
pub(super) fn restart_ingress(action: &Action) -> Result<String, String> {
    if action.name != "landing-restart"
        || !action.begin
        || action.role != "line-a"
        || action.commands.len() != 1
    {
        return Err("missing restart ingress census".to_owned());
    }
    let output = command(&action.commands[0], &RESTART_INGRESS_COMMAND, action)?;
    let rows: Vec<_> = output
        .lines()
        .filter(|row| !row.trim().is_empty())
        .collect();
    if rows.len() != 1 {
        return Err("restart requires exactly one witnessed prefix connection".to_owned());
    }
    let fields: Vec<_> = rows[0].split_whitespace().collect();
    if fields.len() != 4
        || fields[2] != "127.0.0.1:9444"
        || fields[0].parse::<u64>().is_err()
        || fields[1].parse::<u64>().is_err()
    {
        return Err("invalid restart ingress socket row".to_owned());
    }
    let peer: std::net::SocketAddr = fields[3]
        .parse()
        .map_err(|_| "invalid restart ingress peer")?;
    if peer.ip() != std::net::IpAddr::from([127, 0, 0, 1]) || peer.port() == 0 {
        return Err("restart ingress peer is not the owned loopback client".to_owned());
    }
    Ok(peer.to_string())
}

/// Exact sockets and command interval witnessed by a successful stale eviction.
/// The caller must verify the action against its cell, role and fixed schedule.
pub(super) fn stale_evictions(action: &Action) -> Result<Vec<(String, u64, u64)>, String> {
    if action.name != "stale" || !action.begin || action.role != "landing" {
        return Ok(Vec::new());
    }
    let command = action.commands.first().ok_or("missing eviction command")?;
    let output = command.stdout.as_deref().ok_or("missing eviction output")?;
    let mut peers = std::collections::BTreeSet::new();
    for row in output.lines().skip(1) {
        let fields: Vec<_> = row.split_whitespace().collect();
        if fields.len() != 5 || fields[0] != "tcp" || fields[3] != "192.0.2.6:9443" {
            return Err("unrecognized stale eviction socket row".to_owned());
        }
        let peer: std::net::SocketAddr = fields[4].parse().map_err(|_| "invalid eviction peer")?;
        if peer.ip() != std::net::IpAddr::from([192, 0, 2, 5])
            || peer.port() == 0
            || !peers.insert(peer.to_string())
        {
            return Err("unexpected or repeated eviction peer".to_owned());
        }
    }
    if peers.is_empty() {
        return Err("empty stale eviction evidence".to_owned());
    }
    Ok(peers
        .into_iter()
        .map(|peer| (peer, command.started_unix_ms, command.completed_unix_ms))
        .collect())
}

pub fn publication(log: &[u8], action: &Action, tolerance: u64) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Record {
        event: String,
        #[serde(rename = "timestampUnixMs")]
        time: u64,
        generation: Option<u64>,
    }
    if !(action.name == "reload" && action.begin
        || matches!(action.name.as_str(), "warm" | "cold") && action.role != "landing")
    {
        return Ok(());
    }
    let text = std::str::from_utf8(log).map_err(|error| error.to_string())?;
    let deadline = action
        .started_unix_ms
        .checked_add(tolerance)
        .ok_or("publication deadline overflow")?;
    let mut count = 0;
    for line in text.lines() {
        let record: Record = serde_json::from_str(line).map_err(|error| error.to_string())?;
        if record.event == "configuration_published"
            && record.time >= action.started_unix_ms
            && record.time <= deadline
        {
            if record.generation.is_none_or(|generation| generation == 0) {
                return Err("reload did not advance the generation".to_owned());
            }
            count += 1;
        }
    }
    if count != 1 {
        return Err("fault action lacks exactly one timely generation publication".to_owned());
    }
    Ok(())
}

pub fn warm_tcp_config(bytes: &[u8]) -> Result<bool, String> {
    #[derive(Deserialize)]
    struct Config {
        outbounds: std::collections::BTreeMap<String, Outbound>,
    }
    #[derive(Deserialize)]
    struct Outbound {
        #[serde(rename = "warmTcp")]
        warm_tcp: Option<bool>,
    }
    let config: Config = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    config
        .outbounds
        .get("landing-1")
        .and_then(|outbound| outbound.warm_tcp)
        .ok_or_else(|| "missing explicit LINE warmTcp setting".to_owned())
}
