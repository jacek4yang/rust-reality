//! Guest-kernel proof that NXR/Handoff UDP leaves LANDING, not LINE.
//!
//! This is not the TCP stability campaign. It boots the same three-guest
//! fixture, then checks one datagram's source address and the bypass, block,
//! and carrier-drop negatives. A host process test cannot satisfy `verdict`.
//!
//! The LINE→LANDING carrier differs by topology:
//!
//! - NXR carries XUDP inside its TCP carrier to `192.0.2.2:18443/tcp`.
//! - Handoff carries authorized datagrams over the native `handoff-udp`
//!   channel ([ADR 0069]) to `192.0.2.2:18443/udp`; no TCP connection to
//!   LANDING exists for a UDP association.
//!
//! LANDING drops every other UDP datagram arriving on `data0`. For Handoff
//! the single exception is the channel port from LINE's address, which is
//! exactly the firewall rule the deployment guide asks operators to add.
//!
//! [ADR 0069]: ../../../../../docs/adr/0069-native-udp-channel-for-handoff-xudp.md

use std::{
    fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use clap::Args;

use super::fixture::Machines;
use crate::{hash, process::Tool};

const LINE: &str = "line-a";
const LANDING: &str = "landing";
const HOME: &str = "/home/rrtest/rr-stability";
const LINE_IP: &str = "192.0.2.1";
const LANDING_IP: &str = "192.0.2.2";
const ORIGIN_IP: &str = "198.51.100.2";
const LANDING_PORT: u16 = 18_443;
const ENTRY_PORT: u16 = 18_444;
const SOCKS_PORT: u16 = 18_445;
const COVER_PORT: u16 = 18_446;
const ECHO_PORT: u16 = 9;
const PAYLOAD: &str = "rr-guest-udp-proof";
const BLOCK_DEST: &str = "10.1.2.3:9";

/// LINE→LANDING carrier the cell expects for its topology.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// NXR TCP carrier to the LANDING listener.
    NxrTcp,
    /// Native Handoff UDP channel to the LANDING UDP listener (ADR 0069).
    HandoffUdp,
}

impl Carrier {
    fn for_topology(topology: &str) -> Self {
        if topology == "handoff" {
            Self::HandoffUdp
        } else {
            Self::NxrTcp
        }
    }

    /// Receipt token, also checked by the four-cell aggregate.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::NxrTcp => "nxr-tcp",
            Self::HandoffUdp => "handoff-udp",
        }
    }

    /// `iptables` protocol of the carrier.
    const fn proto(self) -> &'static str {
        match self {
            Self::NxrTcp => "tcp",
            Self::HandoffUdp => "udp",
        }
    }
}

/// Inputs for one NXR or Handoff guest UDP cell.
#[derive(Args)]
pub struct Plan {
    /// Preserved three-guest QEMU fixture directory.
    #[arg(long)]
    pub fixture: PathBuf,
    /// Fresh evidence directory. Configurations and keys are never written here.
    #[arg(long)]
    pub output: PathBuf,
    /// Frozen rust-reality executable staged into both guests.
    #[arg(long)]
    pub candidate: PathBuf,
    /// Pinned OpenSSL used on the host to mint the REALITY cover certificate.
    #[arg(long)]
    pub openssl: PathBuf,
    /// Static `rr-udp-probe` staged onto the LINE guest.
    #[arg(long)]
    pub probe: PathBuf,
    /// Static or guest-glibc `rr-udp-echo` staged onto LANDING.
    #[arg(long)]
    pub echo: PathBuf,
    /// `nxr` or `handoff`.
    #[arg(long)]
    pub topology: String,
    /// Use the same 1-vCPU/1-GiB LANDING profile as the TCP cells.
    #[arg(long)]
    pub constrained: bool,
}

/// Facts the cell observed. [`verdict`] accepts nothing else.
#[allow(
    clippy::struct_excessive_bools,
    reason = "each flag is an independent guest observation the receipt names separately"
)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// Must be `guest-kernel`.
    pub layer: String,
    /// `ss -ltn` on LANDING contains `192.0.2.2:18443`.
    pub landing_listen: bool,
    /// `ss -ltn` on LINE contains the entry port.
    pub line_entry_listen: bool,
    /// `ss -ltn` on LINE contains the SOCKS port.
    pub line_socks_listen: bool,
    /// Success probe stdout.
    pub success_probe: String,
    /// Echo peer IP after the success probe.
    pub success_peer: String,
    /// Carrier the topology requires.
    pub carrier: Carrier,
    /// The topology's LINE→LANDING carrier was observed while the probe held
    /// the association: `ss -tn` on LANDING for NXR, a connected UDP socket
    /// from LINE to `192.0.2.2:18443` for Handoff.
    pub carrier_established: bool,
    /// Handoff only: no LINE→LANDING TCP connection existed while the probe
    /// held the association. Always true for NXR.
    pub no_tcp_for_udp: bool,
    /// Bypass probe stdout.
    pub bypass_probe: String,
    /// Echo log did not grow during the bypass attempt.
    pub bypass_echo_unchanged: bool,
    /// Block-destination probe stdout.
    pub block_probe: String,
    /// Echo log did not grow during the block attempt.
    pub block_echo_unchanged: bool,
    /// Probe stdout while the carrier port was dropped.
    pub fault_drop_probe: String,
    /// Probe stdout after the drop rule was removed.
    pub fault_restore_probe: String,
    /// Echo peer IP after the restored probe.
    pub fault_restore_peer: String,
    /// data0 UDP DROP rules were installed before the successful probes.
    pub data_nic_udp_dropped: bool,
    /// LINE `/proc/sys/kernel/random/boot_id`.
    pub line_boot_id: String,
    /// LANDING boot id. Must differ from LINE.
    pub landing_boot_id: String,
    /// LINE `uname -r`.
    pub line_kernel: String,
    /// LANDING `uname -r`.
    pub landing_kernel: String,
}

/// Fail closed unless every guest-identity check holds.
///
/// # Errors
/// Returns the first missing or contradictory observation.
pub fn verdict(obs: &Observation) -> Result<(), String> {
    if obs.layer != "guest-kernel" {
        return Err(format!("layer {}", obs.layer));
    }
    if obs.line_boot_id.is_empty()
        || obs.landing_boot_id.is_empty()
        || obs.line_boot_id == obs.landing_boot_id
    {
        return Err("guest boot ids are missing or identical".to_owned());
    }
    if obs.line_kernel.is_empty() || obs.landing_kernel.is_empty() {
        return Err("guest kernel strings are missing".to_owned());
    }
    if !obs.landing_listen || !obs.line_entry_listen || !obs.line_socks_listen {
        return Err("required listeners were absent".to_owned());
    }
    if !obs.success_probe.starts_with("probe=PASS") {
        return Err(format!("success probe {}", obs.success_probe));
    }
    // LANDING binds egress UDP to its listener address, so the origin peer is
    // 192.0.2.2, not the veth address used by an unbound probe.
    if obs.success_peer != LANDING_IP {
        return Err(format!("udp peer {}", obs.success_peer));
    }
    if !obs.carrier_established {
        return Err(format!(
            "LINE to LANDING {} carrier was not established",
            obs.carrier.token()
        ));
    }
    if !obs.no_tcp_for_udp {
        return Err("Handoff UDP association used a LINE to LANDING TCP connection".to_owned());
    }
    if !obs.bypass_probe.starts_with("probe=FAIL") || !obs.bypass_echo_unchanged {
        return Err("bypass was not rejected".to_owned());
    }
    if !obs.block_probe.starts_with("probe=FAIL") || !obs.block_echo_unchanged {
        return Err("block destination was not rejected".to_owned());
    }
    if !obs.fault_drop_probe.starts_with("probe=FAIL") {
        return Err("carrier drop did not reject the probe".to_owned());
    }
    if !obs.fault_restore_probe.starts_with("probe=PASS") || obs.fault_restore_peer != LANDING_IP {
        return Err(format!(
            "restore probe {} peer {}",
            obs.fault_restore_probe, obs.fault_restore_peer
        ));
    }
    if !obs.data_nic_udp_dropped {
        return Err("data-nic UDP drop was not installed".to_owned());
    }
    Ok(())
}

/// Boot the fixture, prove one topology, and always finalize the guests.
///
/// # Errors
/// Returns boot, guest, or verdict failures. A failed cell still writes
/// `verdict=FAIL` and never `verdict=PASS`.
pub fn run(repo: &Path, plan: &Plan) -> Result<(), String> {
    if plan.topology != "nxr" && plan.topology != "handoff" {
        return Err(format!(
            "topology must be nxr or handoff, got {}",
            plan.topology
        ));
    }
    for (label, path) in [
        ("candidate", &plan.candidate),
        ("openssl", &plan.openssl),
        ("probe", &plan.probe),
        ("echo", &plan.echo),
    ] {
        if !path.is_file() {
            return Err(format!("{label} is not a file: {}", path.display()));
        }
    }
    let mut machines = match Machines::start(&plan.fixture, &plan.output, plan.constrained) {
        Ok(machines) => machines,
        Err(error) => {
            let _ = fs::create_dir_all(&plan.output);
            let _ = write_fail(&plan.output, &error);
            return Err(error);
        }
    };
    let result = execute(repo, plan, &machines);
    let finalized = machines.finalize();
    match (result, finalized) {
        (Err(primary), Err(secondary)) => {
            Err(format!("{primary}; finalize also failed: {secondary}"))
        }
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn execute(repo: &Path, plan: &Plan, machines: &Machines) -> Result<(), String> {
    let source = git_head(repo)?;
    let candidate_sha = hash::sha256_file(&plan.candidate)?;
    let profile = if plan.constrained {
        "constrained"
    } else {
        "ordinary"
    };
    let mut secrets = Vec::new();
    let proved = prove(plan, machines, &mut secrets).map_err(|error| redact(&error, &secrets));
    match proved {
        Ok(obs) => {
            verdict(&obs)?;
            let census = GuestCensus {
                line_nproc: trimmed(machines, LINE, "nproc")?,
                landing_nproc: trimmed(machines, LANDING, "nproc")?,
                line_mem: trimmed(machines, LINE, "awk '/MemTotal/ {print $2}' /proc/meminfo")?,
                landing_mem: trimmed(
                    machines,
                    LANDING,
                    "awk '/MemTotal/ {print $2}' /proc/meminfo",
                )?,
            };
            write_pass(plan, &source, &candidate_sha, profile, &obs, &census)?;
            Ok(())
        }
        Err(error) => {
            let tails = log_tails(machines);
            let _ = fs::write(plan.output.join("diagnostics.txt"), &tails);
            let _ = write_fail(&plan.output, &format!("{error}\n{tails}"));
            Err(error)
        }
    }
}

fn prove(
    plan: &Plan,
    machines: &Machines,
    secrets: &mut Vec<String>,
) -> Result<Observation, String> {
    machines.prepare_inputs(LINE)?;
    machines.prepare_inputs(LANDING)?;
    let carrier = Carrier::for_topology(&plan.topology);
    install_iptables(machines)?;
    let private = private_dir()?;
    let configs = configs(plan, &private, secrets)?;
    stage_assets(plan, machines, &private, &configs)?;
    start_origin(machines)?;
    install_udp_drop(machines, carrier)?;
    start_cover(machines)?;
    start_product(machines, LANDING, "landing.json", "landing.log")?;
    start_product(machines, LINE, "entry.json", "entry.log")?;
    start_product(machines, LINE, "client.json", "client.log")?;
    let landing_listen = wait_listen(machines, LANDING, &format!("{LANDING_IP}:{LANDING_PORT}"))?;
    let line_entry_listen = wait_listen(machines, LINE, &format!("127.0.0.1:{ENTRY_PORT}"))?;
    let line_socks_listen = wait_listen(machines, LINE, &format!("127.0.0.1:{SOCKS_PORT}"))?;
    let (success_probe, success_peer, held) =
        held_probe(machines, carrier, &format!("{ORIGIN_IP}:{ECHO_PORT}"))?;
    let before_bypass = echo_lines(machines)?;
    let bypass_probe = quick_probe(
        machines,
        &format!(
            "./rr-udp-probe --raw-dest {ORIGIN_IP}:{ECHO_PORT} --timeout-ms 2000 --payload {PAYLOAD}"
        ),
    )?;
    let bypass_echo_unchanged = echo_lines(machines)? == before_bypass;
    let before_block = echo_lines(machines)?;
    let block_probe = quick_probe(
        machines,
        &format!(
            "./rr-udp-probe --socks 127.0.0.1:{SOCKS_PORT} --dest {BLOCK_DEST} --timeout-ms 5000 --payload {PAYLOAD}"
        ),
    )?;
    let block_echo_unchanged = echo_lines(machines)? == before_block;
    guest(
        machines,
        LANDING,
        &format!(
            "sudo iptables -I INPUT 1 -i data0 -p {} --dport {LANDING_PORT} -j DROP",
            carrier.proto()
        ),
        Duration::from_secs(15),
    )?;
    let fault_drop_probe = quick_probe(
        machines,
        &format!(
            "./rr-udp-probe --socks 127.0.0.1:{SOCKS_PORT} --dest {ORIGIN_IP}:{ECHO_PORT} --timeout-ms 5000 --payload {PAYLOAD}"
        ),
    )?;
    guest(
        machines,
        LANDING,
        &format!(
            "sudo iptables -D INPUT -i data0 -p {} --dport {LANDING_PORT} -j DROP",
            carrier.proto()
        ),
        Duration::from_secs(15),
    )?;
    let (fault_restore_probe, fault_restore_peer, _) =
        held_probe(machines, carrier, &format!("{ORIGIN_IP}:{ECHO_PORT}"))?;
    let line_boot_id = trimmed(machines, LINE, "cat /proc/sys/kernel/random/boot_id")?;
    let landing_boot_id = trimmed(machines, LANDING, "cat /proc/sys/kernel/random/boot_id")?;
    let line_kernel = trimmed(machines, LINE, "uname -r")?;
    let landing_kernel = trimmed(machines, LANDING, "uname -r")?;
    let _ = fs::remove_dir_all(&private);
    Ok(Observation {
        layer: "guest-kernel".to_owned(),
        landing_listen,
        line_entry_listen,
        line_socks_listen,
        success_probe,
        success_peer,
        carrier,
        carrier_established: held.established,
        no_tcp_for_udp: held.no_tcp,
        bypass_probe,
        bypass_echo_unchanged,
        block_probe,
        block_echo_unchanged,
        fault_drop_probe,
        fault_restore_probe,
        fault_restore_peer,
        data_nic_udp_dropped: true,
        line_boot_id,
        landing_boot_id,
        line_kernel,
        landing_kernel,
    })
}

fn install_iptables(machines: &Machines) -> Result<(), String> {
    for role in [LINE, LANDING] {
        guest(
            machines,
            role,
            "sudo DEBIAN_FRONTEND=noninteractive apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iptables",
            Duration::from_secs(300),
        )?;
    }
    Ok(())
}

fn install_udp_drop(machines: &Machines, carrier: Carrier) -> Result<(), String> {
    guest(
        machines,
        LANDING,
        "ip -br link show data0",
        Duration::from_secs(15),
    )?;
    guest(
        machines,
        LANDING,
        "sudo iptables -P FORWARD DROP && sudo iptables -I INPUT -i data0 -p udp -j DROP && sudo iptables -I FORWARD -i data0 -p udp -j DROP",
        Duration::from_secs(15),
    )?;
    if carrier == Carrier::HandoffUdp {
        // The documented LANDING firewall rule: admit the native channel port
        // from LINE only. Inserted above the blanket drop, so any other UDP on
        // data0 (including LINE→origin bypass) is still dropped.
        guest(
            machines,
            LANDING,
            &udp_channel_accept_rule(),
            Duration::from_secs(15),
        )?;
    }
    Ok(())
}

fn udp_channel_accept_rule() -> String {
    format!(
        "sudo iptables -I INPUT 1 -i data0 -p udp -s {LINE_IP} -d {LANDING_IP} --dport {LANDING_PORT} -j ACCEPT"
    )
}

fn start_origin(machines: &Machines) -> Result<(), String> {
    guest(
        machines,
        LANDING,
        "sudo ip netns add rr-origin && sudo ip link add veth-origin type veth peer name veth-land && sudo ip link set veth-land netns rr-origin && sudo ip addr add 198.51.100.1/30 dev veth-origin && sudo ip link set veth-origin up && sudo ip netns exec rr-origin ip addr add 198.51.100.2/30 dev veth-land && sudo ip netns exec rr-origin ip link set veth-land up && sudo ip netns exec rr-origin ip link set lo up && sudo ip netns exec rr-origin ip route add 192.0.2.2/32 via 198.51.100.1 && sudo sysctl -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.veth-origin.rp_filter=0 net.ipv4.conf.default.rp_filter=0",
        Duration::from_secs(20),
    )?;
    guest(
        machines,
        LANDING,
        &format!(
            "sudo -n bash -c 'ip netns exec rr-origin {HOME}/rr-udp-echo --bind {ORIGIN_IP}:{ECHO_PORT} --log {HOME}/echo.log >{HOME}/echo-server.log 2>&1 & echo $! >{HOME}/echo.pid'"
        ),
        Duration::from_secs(15),
    )?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let sockets = guest(
            machines,
            LANDING,
            "sudo ip netns exec rr-origin ss -uln",
            Duration::from_secs(15),
        )?;
        if sockets.contains(&format!("{ORIGIN_IP}:{ECHO_PORT}")) || sockets.contains(":9") {
            break;
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("echo not listening; {}", log_tails(machines)));
        }
        thread::sleep(Duration::from_millis(200));
    }
    let raw = guest(
        machines,
        LANDING,
        &format!(
            "{HOME}/rr-udp-probe --raw-dest {ORIGIN_IP}:{ECHO_PORT} --timeout-ms 3000 --payload {PAYLOAD}"
        ),
        Duration::from_secs(15),
    )?;
    if !raw.contains("probe=PASS") {
        return Err(format!(
            "landing cannot reach origin: {raw}; {}",
            log_tails(machines)
        ));
    }
    let bound = guest(
        machines,
        LANDING,
        "python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"192.0.2.2\", 0)); s.settimeout(3); s.sendto(b\"rr-guest-udp-proof\", (\"198.51.100.2\", 9)); data, peer = s.recvfrom(64); assert data==b\"rr-guest-udp-proof\", data; print(\"bound-probe=PASS\", peer[0])'",
        Duration::from_secs(15),
    )?;
    if !bound.contains("bound-probe=PASS") {
        return Err(format!(
            "landing bound to {LANDING_IP} cannot reach origin: {bound}; {}",
            log_tails(machines)
        ));
    }
    Ok(())
}

fn start_cover(machines: &Machines) -> Result<(), String> {
    guest(
        machines,
        LINE,
        &format!(
            "cd {HOME} && OPENSSL_CONF={HOME}/openssl.cnf /usr/bin/setsid --fork {HOME}/openssl s_server -tls1_3 -quiet -accept 127.0.0.1:{COVER_PORT} -cert {HOME}/cover.crt -key {HOME}/cover.key > cover.log 2>&1 < /dev/null"
        ),
        Duration::from_secs(15),
    )?;
    wait_listen(machines, LINE, &format!("127.0.0.1:{COVER_PORT}")).map(|_| ())
}

fn start_product(machines: &Machines, role: &str, config: &str, log: &str) -> Result<(), String> {
    guest(
        machines,
        role,
        &format!(
            "cd {HOME} && /usr/bin/setsid --fork {HOME}/rust-reality run --config {HOME}/{config} > {log} 2>&1 < /dev/null"
        ),
        Duration::from_secs(15),
    )?;
    Ok(())
}

/// Carrier facts observed while a held probe kept its association open.
struct Held {
    established: bool,
    no_tcp: bool,
}

fn held_probe(
    machines: &Machines,
    carrier: Carrier,
    dest: &str,
) -> Result<(String, String, Held), String> {
    let before = echo_lines(machines)?;
    guest(
        machines,
        LINE,
        &format!(
            "cd {HOME} && /usr/bin/setsid --fork ./rr-udp-probe --socks 127.0.0.1:{SOCKS_PORT} --dest {dest} --payload {PAYLOAD} --timeout-ms 20000 --hold-ms 20000 > held.out 2> held.err < /dev/null"
        ),
        Duration::from_secs(15),
    )?;
    let stdout = poll_stdout(machines, LINE, "held.out", Duration::from_secs(25))?;
    if !stdout.starts_with("probe=PASS") {
        let _ = guest(
            machines,
            LINE,
            "sudo pkill -x rr-udp-probe || true",
            Duration::from_secs(15),
        );
        return Err(format!("success probe {stdout}; {}", log_tails(machines)));
    }
    let held = observe_carrier(machines, carrier)?;
    let peer = wait_new_peer(machines, before)?;
    let _ = guest(
        machines,
        LINE,
        "sudo pkill -x rr-udp-probe || true",
        Duration::from_secs(15),
    );
    Ok((stdout, peer, held))
}

fn quick_probe(machines: &Machines, command: &str) -> Result<String, String> {
    guest(
        machines,
        LINE,
        &format!(
            "cd {HOME} && /usr/bin/setsid --fork {command} > quick.out 2> quick.err < /dev/null"
        ),
        Duration::from_secs(15),
    )?;
    let stdout = poll_stdout(machines, LINE, "quick.out", Duration::from_secs(8))?;
    let _ = guest(
        machines,
        LINE,
        "sudo pkill -x rr-udp-probe || true",
        Duration::from_secs(15),
    );
    Ok(stdout)
}

fn poll_stdout(
    machines: &Machines,
    role: &str,
    name: &str,
    budget: Duration,
) -> Result<String, String> {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let text = guest(
            machines,
            role,
            &format!("cat {HOME}/{name} || true"),
            Duration::from_secs(15),
        )?;
        if let Some(line) = text.lines().find(|line| line.starts_with("probe=")) {
            return Ok(line.trim().to_owned());
        }
        if std::time::Instant::now() >= deadline {
            return Ok("probe=FAIL reason=no-stdout".to_owned());
        }
        thread::sleep(Duration::from_millis(400));
    }
}

fn observe_carrier(machines: &Machines, carrier: Carrier) -> Result<Held, String> {
    let landing_tcp = guest(machines, LANDING, "ss -tn", Duration::from_secs(15))?;
    let tcp = tcp_carrier_seen(&landing_tcp);
    match carrier {
        Carrier::NxrTcp => Ok(Held {
            established: tcp,
            no_tcp: true,
        }),
        Carrier::HandoffUdp => {
            let line_udp = guest(machines, LINE, "ss -un", Duration::from_secs(15))?;
            Ok(Held {
                established: udp_channel_seen(&line_udp),
                no_tcp: !tcp,
            })
        }
    }
}

/// `ss -tn` on LANDING shows a LINE connection to the LANDING listener.
fn tcp_carrier_seen(ss_tn: &str) -> bool {
    ss_pair_seen(ss_tn, |local, peer| {
        local == format!("{LANDING_IP}:{LANDING_PORT}") && host(peer) == LINE_IP
    })
}

/// `ss -un` on LINE shows a connected socket from LINE to the LANDING UDP
/// listener: the native channel session of the held association.
fn udp_channel_seen(ss_un: &str) -> bool {
    ss_pair_seen(ss_un, |local, peer| {
        host(local) == LINE_IP && peer == format!("{LANDING_IP}:{LANDING_PORT}")
    })
}

/// `ss` omits the State column when the filter selects one state (as
/// `ss -un` does), so match any adjacent local/peer address pair.
fn ss_pair_seen(text: &str, matches: impl Fn(&str, &str) -> bool) -> bool {
    text.lines().any(|line| {
        let fields: Vec<String> = line.split_whitespace().map(unmap).collect();
        fields.windows(2).any(|pair| matches(&pair[0], &pair[1]))
    })
}

/// Normalize `[::ffff:a.b.c.d]:p` to `a.b.c.d:p`.
fn unmap(field: &str) -> String {
    field
        .strip_prefix("[::ffff:")
        .and_then(|rest| rest.split_once(']'))
        .map_or_else(|| field.to_owned(), |(ip, port)| format!("{ip}{port}"))
}

fn host(address: &str) -> &str {
    address.rsplit_once(':').map_or(address, |(ip, _)| ip)
}

fn wait_new_peer(machines: &Machines, before: usize) -> Result<String, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if echo_lines(machines)? > before {
            return last_peer(machines);
        }
        if std::time::Instant::now() >= deadline {
            return Err("echo log did not grow".to_owned());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn last_peer(machines: &Machines) -> Result<String, String> {
    let text = guest(
        machines,
        LANDING,
        &format!("sudo cat {HOME}/echo.log"),
        Duration::from_secs(15),
    )?;
    let line = text.lines().next_back().ok_or("empty echo log")?;
    line.split_whitespace()
        .find_map(|field| field.strip_prefix("peer="))
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("echo line has no peer: {line}"))
}

fn echo_lines(machines: &Machines) -> Result<usize, String> {
    let text = guest(
        machines,
        LANDING,
        &format!("sudo wc -l < {HOME}/echo.log || echo 0"),
        Duration::from_secs(15),
    )?;
    text.trim()
        .lines()
        .next_back()
        .unwrap_or("0")
        .trim()
        .parse()
        .map_err(|_| format!("echo line count {text}"))
}

fn wait_listen(machines: &Machines, role: &str, needle: &str) -> Result<bool, String> {
    for _ in 0..25 {
        let text = guest(machines, role, "ss -ltn", Duration::from_secs(15))?;
        if text.contains(needle) {
            return Ok(true);
        }
        thread::sleep(Duration::from_secs(1));
    }
    let log = if role == LANDING {
        "landing.log"
    } else {
        "entry.log"
    };
    let tail = guest(
        machines,
        role,
        &format!("tail -n 40 {HOME}/{log} {HOME}/client.log {HOME}/cover.log || true"),
        Duration::from_secs(15),
    )
    .unwrap_or_default();
    Err(format!("listener {needle} absent on {role}; tail={tail}"))
}

fn stage_assets(
    plan: &Plan,
    machines: &Machines,
    private: &Path,
    configs: &Configs,
) -> Result<(), String> {
    fs::write(private.join("landing.json"), &configs.landing).map_err(|error| error.to_string())?;
    fs::write(private.join("entry.json"), &configs.entry).map_err(|error| error.to_string())?;
    fs::write(private.join("client.json"), &configs.client).map_err(|error| error.to_string())?;
    machines.stage(LANDING, &plan.candidate, "rust-reality")?;
    machines.stage(LANDING, &plan.echo, "rr-udp-echo")?;
    machines.stage(LANDING, &plan.probe, "rr-udp-probe")?;
    machines.stage(LANDING, &private.join("landing.json"), "landing.json")?;
    machines.stage(LINE, &plan.candidate, "rust-reality")?;
    machines.stage(LINE, &plan.probe, "rr-udp-probe")?;
    machines.stage(LINE, &plan.openssl, "openssl")?;
    let conf = crate::bench::no_ccs::colocated_openssl_conf(&plan.openssl)
        .ok_or_else(|| format!("openssl.cnf missing beside {}", plan.openssl.display()))?;
    machines.stage(LINE, &conf, "openssl.cnf")?;
    machines.stage(LINE, &private.join("cover.crt"), "cover.crt")?;
    machines.stage(LINE, &private.join("cover.key"), "cover.key")?;
    machines.stage(LINE, &private.join("entry.json"), "entry.json")?;
    machines.stage(LINE, &private.join("client.json"), "client.json")?;
    guest(
        machines,
        LANDING,
        &format!("chmod 0755 {HOME}/rust-reality {HOME}/rr-udp-echo {HOME}/rr-udp-probe"),
        Duration::from_secs(15),
    )?;
    guest(
        machines,
        LINE,
        &format!("chmod 0755 {HOME}/rust-reality {HOME}/rr-udp-probe {HOME}/openssl"),
        Duration::from_secs(15),
    )?;
    Ok(())
}

fn log_tails(machines: &Machines) -> String {
    let mut out = String::new();
    for (role, script) in [
        (
            LINE,
            format!(
                "tail -n 40 {HOME}/cover.log {HOME}/entry.log {HOME}/client.log {HOME}/held.err {HOME}/quick.err 2>/dev/null || true"
            ),
        ),
        (
            LANDING,
            format!(
                "sudo tail -n 40 {HOME}/landing.log {HOME}/echo.log {HOME}/echo-server.log 2>/dev/null || true; echo '---ss---'; sudo ip netns exec rr-origin ss -uln; ss -ltn; ss -tn"
            ),
        ),
    ] {
        let text =
            guest(machines, role, &script, Duration::from_secs(15)).unwrap_or_else(|error| error);
        out.push_str(role);
        out.push('\n');
        out.push_str(&text);
        out.push('\n');
    }
    out
}

struct Configs {
    landing: String,
    entry: String,
    client: String,
}

struct GuestCensus {
    line_nproc: String,
    landing_nproc: String,
    line_mem: String,
    landing_mem: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "NXR and Handoff JSON stay adjacent so field names cannot drift from the e2e fixtures"
)]
fn configs(plan: &Plan, private: &Path, secrets: &mut Vec<String>) -> Result<Configs, String> {
    mint_cover(plan, private)?;
    let user_id = generate(plan, &["uuid"])?;
    let short_id = generate(plan, &["short-id"])?;
    let psk = generate(plan, &["psk"])?;
    let (reality_private, reality_public) = x25519(plan)?;
    secrets.extend([
        user_id.clone(),
        short_id.clone(),
        psk.clone(),
        reality_private.clone(),
        reality_public.clone(),
    ]);
    let (landing, entry) = if plan.topology == "handoff" {
        let (landing_private, landing_public) = x25519(plan)?;
        secrets.extend([landing_private.clone(), landing_public.clone()]);
        (
            format!(
                r#"{{
  "role": "landing",
  "listeners": [{{ "port": {LANDING_PORT}, "ip": "ipv4Only", "ipv4": "{LANDING_IP}" }}],
  "landing": {{ "protocol": "handoff", "psk": "{psk}", "privateKey": "{landing_private}" }}
}}
"#
            ),
            format!(
                r#"{{
  "role": "entry",
  "listeners": [{{ "port": {ENTRY_PORT}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "127.0.0.1:{COVER_PORT}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{ "id": "{user_id}", "shortIds": ["{short_id}"], "label": "handoff-xudp" }}],
  "outbounds": {{
    "landing-1": {{
      "type": "handoff",
      "address": "{LANDING_IP}",
      "port": {LANDING_PORT},
      "psk": "{psk}",
      "landingPublicKey": "{landing_public}",
      "warmTcp": false
    }}
  }},
  "routing": {{
    "default": "landing-1",
    "rules": [{{ "name": "block-private-ten", "ip": ["10.0.0.0/8"], "outbound": "block" }}]
  }}
}}
"#
            ),
        )
    } else {
        (
            format!(
                r#"{{
  "role": "landing",
  "listeners": [{{ "port": {LANDING_PORT}, "ip": "ipv4Only", "ipv4": "{LANDING_IP}" }}],
  "landing": {{ "protocol": "nxr", "psk": "{psk}" }}
}}
"#
            ),
            format!(
                r#"{{
  "role": "entry",
  "listeners": [{{ "port": {ENTRY_PORT}, "ipv4": "127.0.0.1" }}],
  "reality": {{
    "cover": "127.0.0.1:{COVER_PORT}",
    "privateKey": "{reality_private}",
    "serverNames": ["localhost"],
    "coverOptimization": {{ "enabled": false }}
  }},
  "users": [{{ "id": "{user_id}", "shortIds": ["{short_id}"], "label": "nxr-xudp" }}],
  "outbounds": {{
    "landing-1": {{
      "type": "nxr",
      "address": "{LANDING_IP}",
      "port": {LANDING_PORT},
      "psk": "{psk}",
      "warmTcp": false
    }}
  }},
  "routing": {{
    "default": "landing-1",
    "rules": [{{ "name": "block-private-ten", "ip": ["10.0.0.0/8"], "outbound": "block" }}]
  }}
}}
"#
            ),
        )
    };
    let client = format!(
        r#"{{
  "role": "client",
  "listeners": [{{ "port": {SOCKS_PORT}, "ipv4": "127.0.0.1" }}],
  "lines": [{{
    "address": "127.0.0.1",
    "port": {ENTRY_PORT},
    "id": "{user_id}",
    "publicKey": "{reality_public}",
    "shortId": "{short_id}",
    "serverName": "localhost"
  }}]
}}
"#
    );
    Ok(Configs {
        landing,
        entry,
        client,
    })
}

fn mint_cover(plan: &Plan, private: &Path) -> Result<(), String> {
    Tool::new(plan.openssl.display().to_string())
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            private.join("cover.key").display().to_string().as_str(),
            "-out",
            private.join("cover.crt").display().to_string().as_str(),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .timeout(Duration::from_secs(30))
        .run()
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn generate(plan: &Plan, args: &[&str]) -> Result<String, String> {
    let mut tool = Tool::new(plan.candidate.display().to_string()).arg("generate");
    tool = tool.args(args.iter().copied());
    let outcome = tool
        .timeout(Duration::from_secs(15))
        .run()
        .map_err(|error| error.to_string())?;
    outcome
        .stdout
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_owned())
        .ok_or_else(|| format!("generate {} produced no output", args.join(" ")))
}

fn x25519(plan: &Plan) -> Result<(String, String), String> {
    let outcome = Tool::new(plan.candidate.display().to_string())
        .args(["generate", "x25519"])
        .timeout(Duration::from_secs(15))
        .run()
        .map_err(|error| error.to_string())?;
    let mut private = None;
    let mut public = None;
    for line in outcome.stdout.lines() {
        let Some((_, value)) = line.split_once(':') else {
            continue;
        };
        if line.starts_with("private key") {
            private = Some(value.trim().to_owned());
        } else if line.starts_with("public key") {
            public = Some(value.trim().to_owned());
        }
    }
    Ok((
        private.ok_or("x25519 private key missing")?,
        public.ok_or("x25519 public key missing")?,
    ))
}

fn private_dir() -> Result<PathBuf, String> {
    let path = std::env::temp_dir().join(format!("rr-udp-guest-{}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&path).map_err(|error| error.to_string())?;
    Ok(path)
}

fn guest(
    machines: &Machines,
    role: &str,
    script: &str,
    timeout: Duration,
) -> Result<String, String> {
    let outcome = machines
        .ssh_within(role, &["bash", "-c", script], timeout)?
        .run()
        .map_err(|error| error.to_string())?;
    Ok(outcome.stdout)
}

fn trimmed(machines: &Machines, role: &str, script: &str) -> Result<String, String> {
    Ok(guest(machines, role, script, Duration::from_secs(15))?
        .trim()
        .to_owned())
}

fn git_head(repo: &Path) -> Result<String, String> {
    let outcome = Tool::new("git")
        .args(["-C", &repo.display().to_string(), "rev-parse", "HEAD"])
        .timeout(Duration::from_secs(10))
        .run()
        .map_err(|error| error.to_string())?;
    Ok(outcome.trimmed_stdout().to_owned())
}

fn write_pass(
    plan: &Plan,
    source: &str,
    candidate_sha: &str,
    profile: &str,
    obs: &Observation,
    census: &GuestCensus,
) -> Result<(), String> {
    let receipt = [
        "verdict=PASS",
        "layer=guest-kernel",
        &format!("source={source}"),
        &format!("topology={}", plan.topology),
        &format!("profile={profile}"),
        &format!("udp_peer={}", obs.success_peer),
        &format!("carrier={}", obs.carrier.token()),
        "bypass=rejected",
        "block_dest=rejected",
        "fault_drop=rejected",
        "fault_restore=accepted",
        "data_nic_udp=dropped",
    ]
    .join("\n")
        + "\n";
    fs::write(plan.output.join("receipt.txt"), receipt).map_err(|error| error.to_string())?;
    let identity = format!(
        "source={source}\ncandidate_sha256={candidate_sha}\ntopology={}\nprofile={profile}\nline_boot_id={}\nlanding_boot_id={}\nline_kernel={}\nlanding_kernel={}\nline_nproc={}\nlanding_nproc={}\nline_mem_total={}\nlanding_mem_total={}\n",
        plan.topology,
        obs.line_boot_id,
        obs.landing_boot_id,
        obs.line_kernel,
        obs.landing_kernel,
        census.line_nproc,
        census.landing_nproc,
        census.line_mem,
        census.landing_mem
    );
    fs::write(plan.output.join("identity.txt"), identity).map_err(|error| error.to_string())?;
    let proof = serde_json::json!({
        "carrier": obs.carrier.token(),
        "carrier_established": obs.carrier_established,
        "no_tcp_for_udp": obs.no_tcp_for_udp,
        "echo_peer": obs.success_peer,
        "success_probe": obs.success_probe,
        "bypass_probe": obs.bypass_probe,
        "block_probe": obs.block_probe,
        "fault_drop_probe": obs.fault_drop_probe,
        "fault_restore_probe": obs.fault_restore_probe,
        "fault_restore_peer": obs.fault_restore_peer,
    });
    fs::write(
        plan.output.join("proof.json"),
        serde_json::to_vec_pretty(&proof).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn write_fail(output: &Path, error: &str) -> Result<(), String> {
    let _ = fs::create_dir_all(output);
    fs::write(
        output.join("receipt.txt"),
        format!("verdict=FAIL\nlayer=guest-kernel\nerror={error}\n"),
    )
    .map_err(|err| err.to_string())
}

fn redact(text: &str, secrets: &[String]) -> String {
    let mut out = text.to_owned();
    for secret in secrets {
        if secret.len() >= 8 {
            out = out.replace(secret, "<redacted>");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> Observation {
        Observation {
            layer: "guest-kernel".to_owned(),
            landing_listen: true,
            line_entry_listen: true,
            line_socks_listen: true,
            success_probe: "probe=PASS".to_owned(),
            success_peer: LANDING_IP.to_owned(),
            carrier: Carrier::NxrTcp,
            carrier_established: true,
            no_tcp_for_udp: true,
            bypass_probe: "probe=FAIL reason=timeout".to_owned(),
            bypass_echo_unchanged: true,
            block_probe: "probe=FAIL reason=timeout".to_owned(),
            block_echo_unchanged: true,
            fault_drop_probe: "probe=FAIL reason=timeout".to_owned(),
            fault_restore_probe: "probe=PASS".to_owned(),
            fault_restore_peer: LANDING_IP.to_owned(),
            data_nic_udp_dropped: true,
            line_boot_id: "line-boot".to_owned(),
            landing_boot_id: "landing-boot".to_owned(),
            line_kernel: "6.8.0-guest".to_owned(),
            landing_kernel: "6.8.0-guest".to_owned(),
        }
    }

    #[test]
    fn observation_peer_from_line_is_rejected() {
        let mut obs = complete();
        obs.success_peer = LINE_IP.to_owned();
        assert!(verdict(&obs).is_err());
    }

    #[test]
    fn observation_missing_bypass_rejection_is_rejected() {
        let mut obs = complete();
        obs.bypass_probe = "probe=PASS".to_owned();
        assert!(verdict(&obs).is_err());
        obs = complete();
        obs.bypass_echo_unchanged = false;
        assert!(verdict(&obs).is_err());
    }

    #[test]
    fn observation_host_process_layer_is_rejected() {
        let mut obs = complete();
        obs.layer = "host-process".to_owned();
        assert!(verdict(&obs).is_err());
    }

    #[test]
    fn observation_failed_success_probe_is_rejected() {
        let mut obs = complete();
        obs.success_probe = "probe=FAIL reason=timeout".to_owned();
        assert!(verdict(&obs).is_err());
    }

    #[test]
    fn observation_restore_peer_other_than_landing_is_rejected() {
        let mut obs = complete();
        obs.fault_restore_peer = LINE_IP.to_owned();
        assert!(verdict(&obs).is_err());
    }

    #[test]
    fn observation_complete_guest_proof_is_accepted() {
        assert!(verdict(&complete()).is_ok());
        let mut obs = complete();
        obs.carrier = Carrier::HandoffUdp;
        assert!(verdict(&obs).is_ok());
    }

    #[test]
    fn observation_handoff_udp_over_tcp_is_rejected() {
        let mut obs = complete();
        obs.carrier = Carrier::HandoffUdp;
        obs.no_tcp_for_udp = false;
        assert!(verdict(&obs).is_err());
    }

    #[test]
    fn observation_missing_carrier_is_rejected() {
        for carrier in [Carrier::NxrTcp, Carrier::HandoffUdp] {
            let mut obs = complete();
            obs.carrier = carrier;
            obs.carrier_established = false;
            assert!(verdict(&obs).is_err());
        }
    }

    #[test]
    fn carrier_follows_topology() {
        assert_eq!(Carrier::for_topology("nxr"), Carrier::NxrTcp);
        assert_eq!(Carrier::for_topology("handoff"), Carrier::HandoffUdp);
        assert_eq!(Carrier::HandoffUdp.proto(), "udp");
        assert_eq!(Carrier::NxrTcp.proto(), "tcp");
    }

    #[test]
    fn handoff_accept_rule_is_scoped_to_line_and_channel_port() {
        let rule = udp_channel_accept_rule();
        assert!(rule.contains("-i data0 -p udp -s 192.0.2.1 -d 192.0.2.2 --dport 18443 -j ACCEPT"));
        assert!(rule.contains("-I INPUT 1 "));
    }

    #[test]
    fn ss_parsers_match_only_line_to_landing() {
        let landing_tcp = "State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
ESTAB 0 0 192.0.2.2:18443 192.0.2.1:40112\n\
ESTAB 0 0 10.0.2.15:22 10.0.2.2:53234\n";
        assert!(tcp_carrier_seen(landing_tcp));
        assert!(!tcp_carrier_seen(
            "ESTAB 0 0 10.0.2.15:22 10.0.2.2:53234\nESTAB 0 0 192.0.2.6:18443 192.0.2.5:1\n"
        ));
        let line_udp = "Recv-Q Send-Q Local Address:Port Peer Address:Port\n\
0 0 192.0.2.1:51820 192.0.2.2:18443\n";
        assert!(udp_channel_seen(line_udp));
        assert!(!udp_channel_seen(
            "ESTAB 0 0 127.0.0.1:5000 127.0.0.1:18445\n"
        ));
        assert!(!udp_channel_seen(
            "ESTAB 0 0 192.0.2.1:51820 192.0.2.2:18444\n"
        ));
        assert!(udp_channel_seen(
            "0 0 [::ffff:192.0.2.1]:51820 [::ffff:192.0.2.2]:18443\n"
        ));
        assert!(!udp_channel_seen("0 0 192.0.2.5:51820 192.0.2.2:18443\n"));
    }
}
