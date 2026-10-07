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
