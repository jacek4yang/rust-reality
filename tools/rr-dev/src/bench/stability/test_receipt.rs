//! Reconstruct deterministic lifecycle coverage from unfiltered libtest output.

use std::collections::{BTreeMap, BTreeSet};

use super::schema::{Check, Contract};

fn count(value: &str, suffix: &str) -> Result<usize, String> {
    let number = value
        .strip_suffix(suffix)
        .ok_or("invalid libtest count label")?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid libtest count".to_owned());
    }
    number
        .parse()
        .map_err(|_| "libtest count overflow".to_owned())
}

fn summary(line: &str) -> Result<(usize, usize), String> {
    let fields: Vec<_> = line
        .strip_prefix("test result: ok. ")
        .ok_or("test suite failed")?
        .split("; ")
        .collect();
    let [passed, failed, ignored, measured, filtered, elapsed] = fields.as_slice() else {
        return Err("incomplete libtest terminal result".to_owned());
    };
    if count(failed, " failed")? != 0
        || count(measured, " measured")? != 0
        || count(filtered, " filtered out")? != 0
    {
        return Err("tests failed or coverage was filtered".to_owned());
    }
    let elapsed = elapsed
        .strip_prefix("finished in ")
        .and_then(|value| value.strip_suffix('s'))
        .ok_or("missing test duration")?;
    if !elapsed
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || !elapsed
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && value >= 0.0)
    {
        return Err("invalid test duration".to_owned());
    }
    Ok((count(passed, " passed")?, count(ignored, " ignored")?))
}

/// Read one complete, unfiltered library-test execution, preserving ignored cases.
///
/// # Errors
/// Rejects missing or duplicate cases, contradictory totals, failures and truncation.
pub fn parse(bytes: &[u8]) -> Result<BTreeSet<String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    if !text.ends_with('\n') {
        return Err("truncated libtest output".to_owned());
    }
    let mut total = None;
    let mut terminal = None;
    let mut cases = BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        if let Some(header) = line.strip_prefix("running ") {
            if total.is_some() || terminal.is_some() || !cases.is_empty() {
                return Err("repeated libtest header".to_owned());
            }
            total = Some(count(
                header,
                if header.ends_with(" tests") {
                    " tests"
                } else {
                    " test"
                },
            )?);
        } else if line.starts_with("test result:") {
            if terminal.is_some() || total.is_none() {
                return Err("repeated or premature libtest terminal result".to_owned());
            }
            terminal = Some(summary(line)?);
        } else {
            let (name, status) = line
                .strip_prefix("test ")
                .and_then(|line| line.split_once(" ... "))
                .ok_or("unexpected libtest output record")?;
            let passed = match status {
                "ok" => true,
                ignored if ignored == "ignored" || ignored.starts_with("ignored, ") => false,
                _ => return Err("test failed or did not complete".to_owned()),
            };
            if total.is_none()
                || terminal.is_some()
                || name.is_empty()
                || name.chars().any(char::is_whitespace)
                || cases.insert(name.to_owned(), passed).is_some()
            {
                return Err("duplicate, late or malformed test case".to_owned());
            }
        }
    }
    let (passed, ignored) = terminal.ok_or("missing libtest terminal result")?;
    if total != Some(cases.len())
        || passed.checked_add(ignored) != total
        || passed != cases.values().filter(|passed| **passed).count()
    {
        return Err("test totals do not reproduce observed cases".to_owned());
    }
    Ok(cases
        .into_iter()
        .filter_map(|(name, passed)| passed.then_some(name))
        .collect())
}

/// Require every frozen lifecycle regression to have actually passed.
///
/// # Errors
/// Rejects another command, empty coverage, ignored or missing required cases.
pub fn verify(bytes: &[u8], check: &Check, contract: &Contract) -> Result<(), String> {
    let required = contract
        .deterministic_tests
        .get(&check.name)
        .ok_or("unknown deterministic check")?;
    if required.is_empty()
        || check.executed_cases != required.len() as u64
        || check.argv
            != [
                "cargo", "test", "--lib", "--locked", "--", "--color", "never",
            ]
    {
        return Err("deterministic check command or case count was substituted".to_owned());
    }
    let passed = parse(bytes)?;
    if required.iter().any(|name| !passed.contains(name)) {
        return Err("a required lifecycle regression did not pass".to_owned());
    }
    Ok(())
}

/// Frozen real-elapsed command. Lifecycle's unfiltered run must not satisfy it.
pub(super) fn long_lived_argv(contract: &Contract) -> Vec<String> {
    [
        "cargo",
        "test",
        "--lib",
        "--locked",
        "--",
        "--color",
        "never",
        "--exact",
        contract.long_lived_test.as_str(),
        "--ignored",
        "--test-threads=1",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn elapsed_ms(value: &str) -> Result<u64, String> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid elapsed seconds".to_owned());
    }
    let seconds: u64 = whole
        .parse()
        .map_err(|_| "elapsed seconds overflow".to_owned())?;
    let mut millis = 0_u64;
    for (index, byte) in fraction.bytes().take(3).enumerate() {
        millis += u64::from(byte - b'0') * 10_u64.pow(2 - u32::try_from(index).unwrap_or(0));
    }
    seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(millis))
        .ok_or_else(|| "elapsed milliseconds overflow".to_owned())
}

/// Require the ignored 600-second matrix to have run and passed on a real clock.
///
/// # Errors
/// Rejects a substituted command, a short run, a failure, or a missing case.
pub fn verify_long_lived(bytes: &[u8], check: &Check, contract: &Contract) -> Result<(), String> {
    if contract.long_lived_minimum_ms != 600_000
        || contract.long_lived_test
            != "server::vision::tests::authenticated_connections_survive_quiet_directions_for_600s"
        || check.name != "long-lived-connections"
        || check.executed_cases != 1
        || check.failed_cases != 0
        || check.argv != long_lived_argv(contract)
    {
        return Err("long-lived command or contract bound was substituted".to_owned());
    }
    let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    if !text.ends_with('\n') {
        return Err("truncated libtest output".to_owned());
    }
    let mut saw_case = false;
    let mut elapsed = None;
    for line in text.lines().filter(|line| !line.is_empty()) {
        if line == format!("test {} ... ok", contract.long_lived_test) {
            if saw_case {
                return Err("duplicated long-lived result".to_owned());
            }
            saw_case = true;
        } else if line.starts_with(&format!("test {} ...", contract.long_lived_test)) {
            return Err("long-lived matrix did not pass".to_owned());
        } else if let Some(rest) = line.strip_prefix("test result: ok. ") {
            if elapsed.is_some() {
                return Err("repeated libtest terminal result".to_owned());
            }
            let duration = rest
                .split("; ")
                .find_map(|field| field.strip_prefix("finished in "))
                .and_then(|value| value.strip_suffix('s'))
                .ok_or("missing long-lived duration")?;
            if rest
                .split("; ")
                .any(|field| field.ends_with(" failed") && field != "0 failed")
            {
                return Err("long-lived suite reported a failure".to_owned());
            }
            elapsed = Some(elapsed_ms(duration)?);
        }
    }
    if !saw_case {
        return Err("long-lived matrix was not executed".to_owned());
    }
    let elapsed = elapsed.ok_or("missing long-lived terminal result")?;
    if elapsed < contract.long_lived_minimum_ms {
        return Err("long-lived matrix did not reach 600 elapsed seconds".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(argv: Vec<String>) -> Check {
        Check {
            name: "long-lived-connections".to_owned(),
            source_commit: "abc".to_owned(),
            candidate_sha256: "d".repeat(64),
            argv,
            exit_code: Some(0),
            completed: true,
            executed_cases: 1,
            failed_cases: 0,
            execution: super::super::schema::Artifact {
                path: "execution.json".to_owned(),
                sha256: "e".repeat(64),
            },
            output: super::super::schema::Artifact {
                path: "output.json".to_owned(),
                sha256: "f".repeat(64),
            },
            observations: Vec::new(),
        }
    }

    fn contract() -> Contract {
        serde_json::from_str(super::super::schema::CONTRACT).expect("compiled contract")
    }

    fn receipt(seconds: &str, status: &str) -> String {
        format!(
            "running 1 test\ntest {} ... {status}\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in {seconds}s\n",
            contract().long_lived_test
        )
    }

    #[test]
    fn long_lived_receipt_requires_the_frozen_600_second_run() {
        let contract = contract();
        assert_eq!(contract.long_lived_minimum_ms, 600_000);
        let check = check(long_lived_argv(&contract));
        assert!(verify_long_lived(receipt("600.00", "ok").as_bytes(), &check, &contract).is_ok());
        assert!(verify_long_lived(receipt("599.999", "ok").as_bytes(), &check, &contract).is_err());
        assert!(
            verify_long_lived(receipt("700", "ignored").as_bytes(), &check, &contract).is_err()
        );
        let mut substituted = check.clone();
        substituted.argv.pop();
        assert!(
            verify_long_lived(receipt("700.00", "ok").as_bytes(), &substituted, &contract).is_err()
        );
    }
}
