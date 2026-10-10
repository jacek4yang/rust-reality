//! Host/guest clock bindings for the single fixed VM workload schedule.
#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use super::schema::{Contract, Observation};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub argv: Vec<String>,
    pub started_unix_ms: u64,
    pub completed_unix_ms: u64,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Probe {
    pub role: String,
    pub phase: String,
    pub boot_id: String,
    pub host_before_unix_ms: u64,
    pub host_after_unix_ms: u64,
    pub date_exit_code: Option<i32>,
    pub date_stdout: String,
    pub date_stderr: String,
    pub commands: Vec<Command>,
    pub errors: Vec<String>,
}

pub fn parse(bytes: &[u8]) -> Result<Probe, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn date_millis(text: &str) -> Result<u64, String> {
    let number = text
        .strip_suffix('\n')
        .ok_or("incomplete guest date receipt")?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("guest date is not an exact integer timestamp".to_owned());
    }
    let value = number.parse().map_err(|_| "guest date overflow")?;
    if value == 0 {
        return Err("zero guest date".to_owned());
    }
    Ok(value)
}

/// Guest clocksource witness. kvm-clock tracks the host after REALTIME is bound.
pub fn clocksource_argv() -> Vec<String> {
    vec![
        "cat".to_owned(),
        "/sys/devices/system/clocksource/clocksource0/current_clocksource".to_owned(),
    ]
}

/// One-shot REALTIME bind. kvm-clock alone does not correct a wrong wall clock
/// inherited from the guest image; without this, start-phase skew can exceed
/// `clock_max_offset_ms` (Frozen 38045882781 line-b ~460–950ms behind host).
pub fn set_argv(time: u64) -> Vec<String> {
    vec![
        "sudo".to_owned(),
        "-n".to_owned(),
        "date".to_owned(),
        "--utc".to_owned(),
        format!("--set=@{}.{:03}", time / 1000, time % 1000),
        "+%s%3N".to_owned(),
    ]
}

fn skew_offset_ms(probe: &Probe, contract: &Contract) -> u64 {
    match probe.phase.as_str() {
        "after" => contract.clock_max_end_offset_ms,
        _ => contract.clock_max_offset_ms,
    }
}

fn bound_error(probe: &Probe) -> String {
    format!(
        "{}: guest clock is not bounded to the host workload schedule",
        probe.role
    )
}

pub fn verify(probe: &Probe, contract: &Contract) -> Result<(), String> {
    let guest = date_millis(&probe.date_stdout)?;
    let offset = skew_offset_ms(probe, contract);
    // Every possible observation instant in the SSH interval must satisfy the
    // skew bound. An overlap with the interval alone would understate uncertainty.
    if !probe.errors.is_empty()
        || probe.date_exit_code != Some(0)
        || !probe.date_stderr.is_empty()
        || probe.boot_id.is_empty()
        || !contract.roles.contains(&probe.role)
        || probe.host_after_unix_ms < probe.host_before_unix_ms
        || probe.host_after_unix_ms - probe.host_before_unix_ms > contract.clock_max_roundtrip_ms
        || guest
            .checked_add(offset)
            .is_none_or(|end| end < probe.host_after_unix_ms)
        || probe
            .host_before_unix_ms
            .checked_add(offset)
            .is_none_or(|end| end < guest)
    {
        return Err(bound_error(probe));
    }
    match probe.phase.as_str() {
        "before" => {
            let [ntp, set, source] = probe.commands.as_slice() else {
                return Err(format!(
                    "{}: missing guest clock setup observations",
                    probe.role
                ));
            };
            if ntp.argv != ["sudo", "-n", "timedatectl", "set-ntp", "false"]
                || set.argv != set_argv(set.started_unix_ms)
                || date_millis(&set.stdout)? != set.started_unix_ms
                || source.argv != clocksource_argv()
                || source.stdout != "kvm-clock\n"
                || ntp.completed_unix_ms > set.started_unix_ms
                || set.completed_unix_ms > source.started_unix_ms
                || source.completed_unix_ms > probe.host_before_unix_ms
            {
                return Err(format!(
                    "{}: clock setup or ordering was substituted",
                    probe.role
                ));
            }
            for command in &probe.commands {
                if command.exit_code != Some(0)
                    || !command.errors.is_empty()
                    || !command.stderr.is_empty()
                    || command.completed_unix_ms < command.started_unix_ms
                {
                    return Err(format!(
                        "{}: guest clock setup did not complete successfully",
                        probe.role
                    ));
                }
            }
        }
        "after" if probe.commands.is_empty() => {}
        _ => {
            return Err(format!(
                "{}: unexpected clock phase or clock mutation after startup",
                probe.role
            ));
        }
    }
    Ok(())
}

pub fn checkpoint(
    raw: &Observation,
    epoch: u64,
    offset: u64,
    contract: &Contract,
) -> Result<(), String> {
    let start = epoch
        .checked_add(offset)
        .ok_or("clock-bound checkpoint overflow")?;
    let earliest = start
        .checked_add(contract.clock_guard_ms())
        .ok_or("clock guard overflow")?;
    let latest = start
        .checked_add(contract.checkpoint_tolerance_ms)
        .ok_or("clock deadline overflow")?;
    if raw.started_unix_ms < earliest
        || raw.completed_unix_ms < raw.started_unix_ms
        || raw
            .completed_unix_ms
            .checked_add(contract.clock_guard_ms())
            .is_none_or(|time| time > latest)
    {
        return Err("checkpoint uncertainty escapes its fixed host-time window".to_owned());
    }
    Ok(())
}

pub fn verify_lifetime(
    probe: &Probe,
    contract: &Contract,
    role: &super::schema::Role,
    before: bool,
    started: u64,
    completed_after: u64,
) -> Result<(), String> {
    verify(probe, contract)?;
    if probe.role != role.name
        || probe.boot_id != role.process.boot_id
        || probe.phase != if before { "before" } else { "after" }
        || (before && probe.host_after_unix_ms > started)
        || (!before && probe.host_before_unix_ms < completed_after)
    {
        return Err("clock receipts do not bind the complete role lifetime".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> Probe {
        Probe {
            role: "landing".to_owned(),
            phase: "before".to_owned(),
            boot_id: "boot".to_owned(),
            host_before_unix_ms: 1030,
            host_after_unix_ms: 1050,
            date_exit_code: Some(0),
            date_stdout: "1040\n".to_owned(),
            date_stderr: String::new(),
            errors: Vec::new(),
            commands: vec![
                Command {
                    argv: ["sudo", "-n", "timedatectl", "set-ntp", "false"]
                        .map(str::to_owned)
                        .to_vec(),
                    started_unix_ms: 1000,
                    completed_unix_ms: 1010,
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    errors: Vec::new(),
                },
                Command {
                    argv: set_argv(1010),
                    started_unix_ms: 1010,
                    completed_unix_ms: 1020,
                    exit_code: Some(0),
                    stdout: "1010\n".to_owned(),
                    stderr: String::new(),
                    errors: Vec::new(),
                },
                Command {
                    argv: clocksource_argv(),
                    started_unix_ms: 1020,
                    completed_unix_ms: 1025,
                    exit_code: Some(0),
                    stdout: "kvm-clock\n".to_owned(),
                    stderr: String::new(),
                    errors: Vec::new(),
                },
            ],
        }
    }

    fn after_probe(guest: u64, host_before: u64, host_after: u64) -> Probe {
        Probe {
            role: "landing".to_owned(),
            phase: "after".to_owned(),
            boot_id: "boot".to_owned(),
            host_before_unix_ms: host_before,
            host_after_unix_ms: host_after,
            date_exit_code: Some(0),
            date_stdout: format!("{guest}\n"),
            date_stderr: String::new(),
            errors: Vec::new(),
            commands: Vec::new(),
        }
    }

    #[test]
    fn shared_epochs_reject_skew_uncertainty_and_missing_setup() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        verify(&probe(), &contract).unwrap();
        for time in [
            "21000\n",
            "1\n",
            "NaN\n",
            "1040",
            "+1040\n",
            "18446744073709551616\n",
        ] {
            let mut changed = probe();
            changed.date_stdout = time.to_owned();
            assert!(verify(&changed, &contract).is_err());
        }
        let mut changed = probe();
        changed.host_after_unix_ms += 1000;
        assert!(verify(&changed, &contract).is_err());
        let mut changed = probe();
        changed.commands.clear();
        assert!(verify(&changed, &contract).is_err());
        let mut changed = probe();
        changed.commands[0].exit_code = Some(1);
        assert!(verify(&changed, &contract).is_err());
        let mut changed = probe();
        changed.commands[2].stdout = "tsc\n".to_owned();
        assert!(verify(&changed, &contract).is_err());
    }

    #[test]
    fn after_phase_allows_end_offset_not_start_offset() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        // Mirrors Frozen 38037827211 landing after: ~421ms ahead of host_after.
        let observed = after_probe(1_791_626_306_275, 1_791_626_305_773, 1_791_626_305_854);
        assert!(
            observed.date_stdout.trim().parse::<u64>().unwrap()
                > observed.host_before_unix_ms + contract.clock_max_offset_ms
        );
        verify(&observed, &contract).unwrap();
        let mut too_far = observed;
        too_far.date_stdout = format!(
            "{}\n",
            too_far.host_before_unix_ms + contract.clock_max_end_offset_ms + 1
        );
        let err = verify(&too_far, &contract).unwrap_err();
        assert!(err.contains("landing: guest clock is not bounded"));
    }

    #[test]
    fn sampling_reserves_clock_uncertainty_inside_the_existing_deadline() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        let mut raw = super::super::schema::parse_observation(include_bytes!(
            "../../../../../fuzz/seeds/stability_evidence/seed_owned_unix.json"
        ))
        .unwrap();
        raw.started_unix_ms = 10_000 + contract.clock_guard_ms();
        raw.completed_unix_ms = 11_000;
        checkpoint(&raw, 10_000, 0, &contract).unwrap();
        raw.started_unix_ms -= 1;
        assert!(checkpoint(&raw, 10_000, 0, &contract).is_err());
        raw.started_unix_ms += 1;
        raw.completed_unix_ms = 12_000 - contract.clock_guard_ms() + 1;
        assert!(checkpoint(&raw, 10_000, 0, &contract).is_err());
        assert!(checkpoint(&raw, u64::MAX, 1, &contract).is_err());
    }

    #[test]
    fn frozen_38045882781_line_b_before_without_set_fails_start_offset() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        // handoff/constrained line-b before: guest ~952ms behind host_after.
        let mut probe = Probe {
            role: "line-b".to_owned(),
            phase: "before".to_owned(),
            boot_id: "dd2b042b-9394-4beb-96f1-3e22b85bcd32".to_owned(),
            host_before_unix_ms: 1_791_630_343_814,
            host_after_unix_ms: 1_791_630_343_824,
            date_exit_code: Some(0),
            date_stdout: "1791630342872\n".to_owned(),
            date_stderr: String::new(),
            errors: Vec::new(),
            commands: vec![
                Command {
                    argv: ["sudo", "-n", "timedatectl", "set-ntp", "false"]
                        .map(str::to_owned)
                        .to_vec(),
                    started_unix_ms: 1_791_630_343_530,
                    completed_unix_ms: 1_791_630_343_803,
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: String::new(),
                    errors: Vec::new(),
                },
                Command {
                    argv: clocksource_argv(),
                    started_unix_ms: 1_791_630_343_803,
                    completed_unix_ms: 1_791_630_343_814,
                    exit_code: Some(0),
                    stdout: "kvm-clock\n".to_owned(),
                    stderr: String::new(),
                    errors: Vec::new(),
                },
            ],
        };
        let err = verify(&probe, &contract).unwrap_err();
        assert!(err.contains("line-b: guest clock is not bounded"), "{err}");
        // nxr/ordinary line-b before: guest ~471ms behind — also fails start offset.
        probe.host_before_unix_ms = 1_791_630_369_026;
        probe.host_after_unix_ms = 1_791_630_369_036;
        probe.date_stdout = "1791630368565\n".to_owned();
        probe.boot_id = "6ea165c3-6495-44a6-8e25-092b941e8436".to_owned();
        let err = verify(&probe, &contract).unwrap_err();
        assert!(err.contains("line-b: guest clock is not bounded"), "{err}");
    }

    #[test]
    fn before_phase_requires_set_then_kvm_clock_witness() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        verify(&probe(), &contract).unwrap();
        let mut missing_set = probe();
        missing_set.commands.remove(1);
        assert!(
            verify(&missing_set, &contract)
                .unwrap_err()
                .contains("missing guest clock setup")
        );
        let mut bad_set_echo = probe();
        bad_set_echo.commands[1].stdout = "999\n".to_owned();
        assert!(
            verify(&bad_set_echo, &contract)
                .unwrap_err()
                .contains("clock setup or ordering was substituted")
        );
    }

    #[test]
    fn after_phase_line_b_behind_under_end_offset_from_frozen() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        // handoff/constrained line-b after: ~951ms behind host_after; passes end offset.
        let observed = Probe {
            role: "line-b".to_owned(),
            phase: "after".to_owned(),
            boot_id: "dd2b042b-9394-4beb-96f1-3e22b85bcd32".to_owned(),
            host_before_unix_ms: 1_791_630_344_918,
            host_after_unix_ms: 1_791_630_344_948,
            date_exit_code: Some(0),
            date_stdout: "1791630343997\n".to_owned(),
            date_stderr: String::new(),
            errors: Vec::new(),
            commands: Vec::new(),
        };
        verify(&observed, &contract).unwrap();
        assert!(
            observed.host_after_unix_ms
                > date_millis(&observed.date_stdout).unwrap() + contract.clock_max_offset_ms
        );
    }

    #[test]
    fn clock_receipts_bind_role_boot_and_complete_lifetime() {
        let contract: Contract = serde_json::from_str(super::super::schema::CONTRACT).unwrap();
        let evidence: super::super::schema::Evidence =
            serde_json::from_value(super::super::tests::fixture()).unwrap();
        let role = &evidence.cells[0].roles[0];
        let mut value = probe();
        value.role.clone_from(&role.name);
        value.boot_id.clone_from(&role.process.boot_id);
        verify_lifetime(&value, &contract, role, true, 1060, 2000).unwrap();
        assert!(verify_lifetime(&value, &contract, role, true, 1049, 2000).is_err());
        assert!(verify_lifetime(&value, &contract, role, false, 1000, 2000).is_err());
        value.phase = "after".to_owned();
        value.commands.clear();
        verify_lifetime(&value, &contract, role, false, 500, 1030).unwrap();
        assert!(verify_lifetime(&value, &contract, role, false, 500, 1031).is_err());
        value.boot_id.push('x');
        assert!(verify_lifetime(&value, &contract, role, false, 500, 1030).is_err());
    }
}
