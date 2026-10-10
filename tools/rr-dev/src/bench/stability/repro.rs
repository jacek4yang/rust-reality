//! Minutes-scale single-fault reproduction for stability gate defects.
//!
//! Ordinary machines cannot host the three-guest QEMU fixture. This path still
//! fail-closes the landing-restart census/ACK contract on synthetic receipts,
//! exercises the wire handshake on loopback, and emits Class A/B/C diagnosis so
//! harness defects are localized without a multi-hour four-cell INVALID.

use super::action;
use clap::Args;
use serde_json::json;
use std::{
    fs,
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    thread,
    time::Duration,
};

/// Inputs for one focused stability fault reproduction.
#[derive(Args)]
pub struct Plan {
    /// Fault name. Only `landing-restart` is implemented for the fast path.
    #[arg(long)]
    pub fault: String,
    /// Fresh directory for retained receipts and the diagnosis report.
    #[arg(long)]
    pub output: PathBuf,
}

use super::diagnosis::classify;

fn valid_line_a() -> serde_json::Value {
    json!({
        "role":"line-a","boot_id":"fixture","started_unix_ms":100,"completed_unix_ms":120,
        "name":"landing-restart","begin":true,"error":null,
        "configuration_sha256":"a".repeat(64),"termination_signal":null,"warm_tcp":true,
        "commands":[
            {
                "argv":["ss","-Hnt","state","established","src","127.0.0.1","(","sport","=",":9444",")"],
                "started_unix_ms":101,"completed_unix_ms":109,"exit_code":0,"stderr":"",
                "stdout":"0 0 127.0.0.1:9444 127.0.0.1:43028\n"
            },
            {
                "argv":action::RESTART_ACK_SEND_ARGV,
                "started_unix_ms":110,"completed_unix_ms":118,"exit_code":0,"stderr":"",
                "stdout":"127.0.0.1:43028\nfixture\n"
            }
        ]
    })
}

fn valid_landing() -> serde_json::Value {
    json!({
        "role":"landing","boot_id":"landing-boot","started_unix_ms":100,"completed_unix_ms":119,
        "name":"landing-restart","begin":true,"error":null,
        "configuration_sha256":"a".repeat(64),"termination_signal":9,"warm_tcp":null,
        "commands":[{
            "argv":action::RESTART_ACK_RECV_ARGV,
            "started_unix_ms":101,"completed_unix_ms":117,"exit_code":0,"stderr":"",
            "stdout":"127.0.0.1:43028\nfixture\n"
        }]
    })
}

fn wire_handshake() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let addr = listener.local_addr().map_err(|error| error.to_string())?;
    let peer = "127.0.0.1:43028".to_owned();
    let boot = "fixture-boot".to_owned();
    let expected_peer = peer.clone();
    let expected_boot = boot.clone();
    let server = thread::spawn(move || -> Result<String, String> {
        let (mut stream, _) = listener
            .accept()
            .map_err(|error| format!("repro ACK accept: {error}"))?;
        let mut buffer = Vec::new();
        stream
            .read_to_end(&mut buffer)
            .map_err(|error| format!("repro ACK read: {error}"))?;
        let text = std::str::from_utf8(&buffer).map_err(|error| error.to_string())?;
        let mut lines = text.lines();
        if lines.next() != Some(action::RESTART_ACK_MAGIC) {
            return Err("repro ACK magic mismatch".to_owned());
        }
        let witnessed = lines.next().unwrap_or_default().to_owned();
        let publisher = lines.next().unwrap_or_default().to_owned();
        if lines.next().is_some() || witnessed != expected_peer || publisher != expected_boot {
            return Err("repro ACK body mismatch".to_owned());
        }
        let reply = format!("{}\n{witnessed}\n", action::RESTART_ACK_ACCEPTED);
        stream
            .write_all(reply.as_bytes())
            .map_err(|error| format!("repro ACK reply: {error}"))?;
        Ok(witnessed)
    });
    thread::sleep(Duration::from_millis(10));
    let mut client = TcpStream::connect(addr).map_err(|error| error.to_string())?;
    let payload = format!("{}\n{peer}\n{boot}\n", action::RESTART_ACK_MAGIC);
    client
        .write_all(payload.as_bytes())
        .map_err(|error| error.to_string())?;
    client
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut reply = Vec::new();
    client
        .read_to_end(&mut reply)
        .map_err(|error| error.to_string())?;
    let text = std::str::from_utf8(&reply).map_err(|error| error.to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some(action::RESTART_ACK_ACCEPTED) || lines.next() != Some(peer.as_str()) {
        return Err("repro ACK accept reply mismatch".to_owned());
    }
    let witnessed = server
        .join()
        .map_err(|_| "repro ACK server panicked".to_owned())??;
    if witnessed != peer {
        return Err("repro ACK peer drifted".to_owned());
    }
    Ok(())
}

/// Run the landing-restart fast reproduction and retain receipts plus diagnosis.
///
/// # Errors
/// Returns when the fault name is unsupported or any fail-closed check fails.
pub fn run(plan: &Plan) -> Result<(), String> {
    if plan.fault != "landing-restart" {
        return Err(format!(
            "stability-repro currently supports only landing-restart; got {}",
            plan.fault
        ));
    }
    fs::create_dir(&plan.output).map_err(|error| format!("fresh repro directory: {error}"))?;
    let mut cases = Vec::new();

    let line_a = action::parse(&serde_json::to_vec(&valid_line_a()).unwrap())?;
    match action::restart_ingress(&line_a) {
        Ok((peer, census_completed)) if peer == "127.0.0.1:43028" && census_completed == 109 => {
            cases.push(json!({"case":"valid-line-a-census-ack","result":"pass","class":null}));
        }
        Ok(other) => {
            return Err(format!("unexpected valid census receipt {other:?}"));
        }
        Err(error) => {
            return Err(format!("valid LINE-A receipt must pass: {error}"));
        }
    }

    let landing = action::parse(&serde_json::to_vec(&valid_landing()).unwrap())?;
    match action::restart_ack(&landing) {
        Ok((peer, completed)) if peer == "127.0.0.1:43028" && completed == 117 => {
            cases.push(json!({"case":"valid-landing-ack","result":"pass","class":null}));
        }
        Ok(other) => return Err(format!("unexpected landing ACK {other:?}")),
        Err(error) => return Err(format!("valid LANDING receipt must pass: {error}")),
    }

    // Historical empty census (Class B harness) must stay INVALID — not rewritten.
    let mut empty = valid_line_a();
    empty["commands"][0]["stdout"] = json!("");
    let empty_action = action::parse(&serde_json::to_vec(&empty).unwrap())?;
    let empty_err = action::restart_ingress(&empty_action)
        .err()
        .ok_or("empty census must fail closed")?;
    assert_eq!(
        empty_err,
        "restart requires exactly one witnessed prefix connection"
    );
    cases.push(json!({
        "case":"historical-empty-census-37886641986",
        "result":"fail-closed",
        "class": classify(&empty_err).label(),
        "message": empty_err,
    }));

    let mut early_ack = valid_line_a();
    early_ack["commands"][1]["started_unix_ms"] = json!(108);
    let early = action::parse(&serde_json::to_vec(&early_ack).unwrap())?;
    let early_err = action::restart_ingress(&early)
        .err()
        .ok_or("ACK before census must fail closed")?;
    cases.push(json!({
        "case":"ack-predates-census",
        "result":"fail-closed",
        "class": classify(&early_err).label(),
        "message": early_err,
    }));

    wire_handshake()?;
    cases.push(json!({"case":"loopback-wire-handshake","result":"pass","class":null}));

    fs::write(
        plan.output.join("line-a-action.json"),
        serde_json::to_vec_pretty(&valid_line_a()).unwrap(),
    )
    .map_err(|error| error.to_string())?;
    fs::write(
        plan.output.join("landing-action.json"),
        serde_json::to_vec_pretty(&valid_landing()).unwrap(),
    )
    .map_err(|error| error.to_string())?;
    let report = json!({
        "schema":"rr-stability-repro/v1",
        "fault":"landing-restart",
        "semantics":"ack-driven-census-before-abort",
        "rejected_mechanism":"RESTART_CENSUS_HOLD_MS wall-clock hold",
        "cases": cases,
        "invocation":"cargo dev bench stability-repro --fault landing-restart --output DIR",
    });
    fs::write(
        plan.output.join("diagnosis.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .map_err(|error| error.to_string())?;
    println!("{}", serde_json::to_string_pretty(&report).unwrap());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::diagnosis::Class;
    use super::*;

    #[test]
    fn empty_census_is_class_b_harness() {
        assert_eq!(
            classify("restart requires exactly one witnessed prefix connection"),
            Class::B
        );
    }

    #[test]
    fn loopback_wire_handshake_round_trips() {
        wire_handshake().unwrap();
    }
}
