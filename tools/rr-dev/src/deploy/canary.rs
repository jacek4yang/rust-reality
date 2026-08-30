//! Fail-closed evaluator for the exact-candidate dual-VPS release canary.
//!
//! Migrated from `evaluate-release-canary.py`. It is a pure function from a
//! recorded canary report to a verdict: every invariant that must hold for a
//! release to promote is checked, and any violation is collected into `reasons`
//! so an operator sees all of them at once. Exit status is three-valued like the
//! performance evaluator: 0 when the canary passes, 1 for a real failure, and 2
//! when the input was inadmissible (unreadable or not a JSON object).
//!
//! The fixed ceilings (FD/thread/RSS recovery, traffic ratios, rejection
//! allowances) are a reviewed release contract, not values supplied by the
//! candidate under test.

use std::path::Path;

use crate::perf::{
    json_in::{self, Value},
    json_out::Json,
};

/// The checks every release canary must report as `true`.
pub const REQUIRED_CHECKS: [&str; 23] = [
    "lineSsh",
    "landingSsh",
    "lineServiceActive",
    "landingServiceActive",
    "linePublicPortsRestricted",
    "landingPublicPortsRestricted",
    "landingFirewallLineOnly",
    "lineCandidateIdentity",
    "landingCandidateIdentity",
    "stockXray",
    "oneMiBIntegrity",
    "largeIntegrity",
    "uploadIntegrity",
    "bidirectionalIntegrity",
    "lineReload",
    "generationRetirement",
    "landingRestart",
    "restartRecovery",
    "coldFallback",
    "warmHandoff",
    "noRestartLoop",
    "noAuthenticationRegression",
    "noReplayRegression",
];

/// The reviewed FD ceilings per host: `(final, peak)`.
const FD_LIMITS: [(&str, i64, i64); 2] = [("line", 768, 2_048), ("landing", 256, 1_024)];

/// The three-valued outcome of evaluating a canary report.
#[derive(Debug)]
pub enum Outcome {
    /// The report was admissible; `verdict` carries the rendered JSON and `ok`.
    Evaluated {
        /// The rendered verdict JSON.
        verdict: String,
        /// Whether the canary passed.
        ok: bool,
    },
    /// The input could not be admitted for evaluation.
    Inadmissible(String),
}

/// Evaluates the canary report at `path`.
///
/// # Errors
///
/// Never returns `Err`; inadmissible input is reported as
/// [`Outcome::Inadmissible`] so the caller maps it to exit code 2.
#[must_use]
pub fn evaluate_file(path: &Path) -> Outcome {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => return Outcome::Inadmissible(format!("{}: {error}", path.display())),
    };
    evaluate_text(&text)
}

/// Evaluates a canary report already held in memory.
///
/// This is the recorded-parity boundary used by the native runner: it must feed
/// its generated report through the same fail-closed evaluator operators invoke
/// on archived evidence.
#[must_use]
pub fn evaluate_text(text: &str) -> Outcome {
    let value = match json_in::parse(text) {
        Ok(value) => value,
        Err(error) => return Outcome::Inadmissible(format!("canary input is not JSON: {error}")),
    };
    if !matches!(value, Value::Object(_)) {
        return Outcome::Inadmissible("canary input must be a JSON object".to_owned());
    }
    let (reasons, candidate, elapsed) = evaluate(&value);
    let ok = reasons.is_empty();
    let verdict = render(&reasons, candidate, elapsed, ok);
    Outcome::Evaluated { verdict, ok }
}

/// Runs the evaluation, returning the reasons, the echoed candidate and elapsed.
fn evaluate(report: &Value) -> (Vec<String>, Option<&Value>, Option<&Value>) {
    let mut reasons = Vec::new();

    if report.optional("schemaVersion").and_then(int) != Some(1) {
        reasons.push("schemaVersion must be 1".to_owned());
    }

    let candidate = report.optional("candidate");
    check_string_fields(
        candidate,
        "candidate",
        &["commit", "sha256", "buildId", "version", "target", "rustc"],
        &mut reasons,
    );
    check_string_fields(
        report.optional("comparator"),
        "comparator",
        &["name", "version", "sha256", "buildId"],
        &mut reasons,
    );

    let elapsed = report.optional("elapsedSeconds");
    match elapsed.and_then(int) {
        Some(value) if (480..=900).contains(&value) => {}
        Some(_) => {
            reasons.push("elapsedSeconds must be in the active-canary range 480..900".to_owned());
        }
        None => reasons.push("elapsedSeconds must be an integer".to_owned()),
    }

    match report.optional("checks") {
        Some(Value::Object(checks)) => {
            for check in REQUIRED_CHECKS {
                if checks.get(check) != Some(&Value::Bool(true)) {
                    reasons.push(format!("required check failed or missing: {check}"));
                }
            }
        }
        _ => reasons.push("checks must be an object".to_owned()),
    }

    let attempted = evaluate_traffic(report, &mut reasons);
    evaluate_handoff_pool(report, &mut reasons);
    evaluate_landing_rejections(report, attempted, &mut reasons);
    reasons.extend(resource_reasons(report));

    (reasons, candidate, elapsed)
}

fn evaluate_traffic(report: &Value, reasons: &mut Vec<String>) -> Option<i64> {
    let Some(Value::Object(traffic)) = report.optional("traffic") else {
        reasons.push("traffic must be an object".to_owned());
        return None;
    };
    let attempted = strict_int(traffic.get("connectionsAttempted"), "traffic.connectionsAttempted", reasons);
    let successful = strict_int(traffic.get("connectionsSuccessful"), "traffic.connectionsSuccessful", reasons);
    if let (Some(attempted), Some(successful)) = (attempted, successful) {
        if attempted < 500 {
            reasons.push("traffic.connectionsAttempted must be at least 500".to_owned());
        }
        if successful < 450 || successful * 100 < attempted * 95 {
            reasons.push("traffic success must be at least 450 and 95%".to_owned());
        }
    }
    attempted
}

fn evaluate_handoff_pool(report: &Value, reasons: &mut Vec<String>) {
    let Some(Value::Object(pool)) = report.optional("handoffPool") else {
        reasons.push("handoffPool must be an object".to_owned());
        return;
    };
    let field = |name: &str, reasons: &mut Vec<String>| {
        strict_int(pool.get(name), &format!("handoffPool.{name}"), reasons)
    };
    let hit = field("checkoutHit", reasons);
    let miss = field("checkoutMiss", reasons);
    let cold = field("coldFallback", reasons);
    let target_peak = field("targetReadyPeak", reasons);
    let max_ready = field("maxReady", reasons);
    let connecting_peak = field("connectingPeak", reasons);
    let max_connecting = field("maxConnecting", reasons);
    if let Some(hit) = hit {
        if hit <= 0 {
            reasons.push("handoff warm checkout was not observed".to_owned());
        }
        if let Some(miss) = miss
            && hit + miss <= 0
        {
            reasons.push("handoff pool recorded no checkout attempts".to_owned());
        }
    }
    if cold == Some(0) || cold.is_some_and(|value| value < 0) {
        reasons.push("handoff cold fallback was not exercised".to_owned());
    }
    if let (Some(target_peak), Some(max_ready)) = (target_peak, max_ready)
        && target_peak > max_ready
    {
        reasons.push("handoff target_ready exceeded maxReady".to_owned());
    }
    if let (Some(connecting_peak), Some(max_connecting)) = (connecting_peak, max_connecting)
        && connecting_peak > max_connecting
    {
        reasons.push("handoff connecting exceeded maxConnecting".to_owned());
    }
}

fn evaluate_landing_rejections(report: &Value, attempted: Option<i64>, reasons: &mut Vec<String>) {
    let Some(Value::Object(rejections)) = report.optional("landingRejections") else {
        reasons.push("landingRejections must be an object".to_owned());
        return;
    };
    let count = strict_int(rejections.get("count"), "landingRejections.count", reasons);
    let authentication = strict_int(
        rejections.get("authenticationOrProtocol"),
        "landingRejections.authenticationOrProtocol",
        reasons,
    );
    if authentication.is_some_and(|value| value != 0) {
        reasons.push("LANDING authentication/protocol rejection observed".to_owned());
    }
    match (count, attempted) {
        (Some(count), Some(attempted)) => {
            let allowed = (attempted / 50).clamp(8, 256);
            if count > allowed {
                reasons.push(format!(
                    "LANDING rejection count {count} exceeded restart allowance {allowed}"
                ));
            }
        }
        (Some(_), None) => {
            reasons.push("cannot bound LANDING rejections without traffic attempts".to_owned());
        }
        _ => {}
    }
}

/// Resource recovery invariants: FD/thread/RSS final and peak ceilings per host.
fn resource_reasons(report: &Value) -> Vec<String> {
    let mut reasons = Vec::new();
    let Some(Value::Object(resources)) = report.optional("resources") else {
        return vec!["resources must be an object".to_owned()];
    };
    for (host, final_fd, peak_fd) in FD_LIMITS {
        let Some(Value::Array(samples)) = resources.get(host) else {
            reasons.push(format!("resources.{host} requires at least 12 samples"));
            continue;
        };
        if samples.len() < 12 {
            reasons.push(format!("resources.{host} requires at least 12 samples"));
            continue;
        }
        let mut normalized: Vec<[i64; 3]> = Vec::with_capacity(samples.len());
        let mut sample_ok = true;
        for (index, sample) in samples.iter().enumerate() {
            let Value::Object(fields) = sample else {
                reasons.push(format!("resources.{host}[{index}] must be an object"));
                sample_ok = false;
                continue;
            };
            let mut row = [0_i64; 3];
            for (slot, name) in ["rssKiB", "fd", "threads"].iter().enumerate() {
                match strict_int(fields.get(*name), &format!("resources.{host}[{index}].{name}"), &mut reasons) {
                    Some(value) => row[slot] = value,
                    None => sample_ok = false,
                }
            }
            normalized.push(row);
        }
        if !sample_ok || normalized.len() != samples.len() {
            continue;
        }
        let first = normalized[0];
        let last = normalized[normalized.len() - 1];
        let peak = [
            normalized.iter().map(|row| row[0]).max().unwrap_or(0),
            normalized.iter().map(|row| row[1]).max().unwrap_or(0),
            normalized.iter().map(|row| row[2]).max().unwrap_or(0),
        ];
        if last[1] > final_fd {
            reasons.push(format!("{host} final FD count exceeded {final_fd}"));
        }
        if peak[1] > peak_fd {
            reasons.push(format!("{host} FD peak exceeded {peak_fd}"));
        }
        if last[2] > first[2] + 8 {
            reasons.push(format!("{host} thread count did not recover within +8"));
        }
        if peak[2] > first[2] + 16 {
            reasons.push(format!("{host} thread peak exceeded baseline +16"));
        }
        if last[0] > first[0] + 32 * 1024 {
            reasons.push(format!("{host} RSS did not recover within +32 MiB"));
        }
        if peak[0] > first[0] + 96 * 1024 {
            reasons.push(format!("{host} RSS peak exceeded baseline +96 MiB"));
        }
    }
    reasons
}

/// Renders the verdict JSON exactly like the Python (`indent=2, sort_keys=True`).
fn render(reasons: &[String], candidate: Option<&Value>, elapsed: Option<&Value>, ok: bool) -> String {
    let verdict = Json::object([
        ("schemaVersion", Json::Int(1)),
        ("gate", Json::string("dual-vps-active-release-canary")),
        ("candidate", candidate.map_or(Json::Null, value_to_json)),
        ("elapsedSeconds", elapsed.map_or(Json::Null, value_to_json)),
        (
            "reasons",
            Json::Array(reasons.iter().cloned().map(Json::string).collect()),
        ),
        ("ok", Json::Bool(ok)),
    ]);
    verdict.to_python_json()
}

fn check_string_fields(object: Option<&Value>, label: &str, fields: &[&str], reasons: &mut Vec<String>) {
    let Some(Value::Object(members)) = object else {
        reasons.push(format!("{label} must be an object"));
        return;
    };
    for field in fields {
        match members.get(*field) {
            Some(Value::Str(text)) if !text.is_empty() => {}
            _ => reasons.push(format!("{label}.{field} must be a non-empty string")),
        }
    }
}

/// Reads a JSON integer, rejecting booleans and floats like the Python `integer`.
fn int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(text) if !text.contains('.') && !text.contains('e') && !text.contains('E') => {
            text.parse().ok()
        }
        _ => None,
    }
}

/// Reads a required integer field, recording a typed reason when it is absent or
/// not an integer, matching the Python `integer()` raising on non-int.
fn strict_int(value: Option<&Value>, field: &str, reasons: &mut Vec<String>) -> Option<i64> {
    let parsed = value.and_then(int);
    if parsed.is_none() {
        reasons.push(format!("{field} must be an integer"));
    }
    parsed
}

fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(flag) => Json::Bool(*flag),
        Value::Number(text) => text
            .parse::<i64>()
            .map(Json::Int)
            .or_else(|_| text.parse::<f64>().map(Json::Float))
            .unwrap_or(Json::Null),
        Value::Str(text) => Json::Str(text.clone()),
        Value::Array(items) => Json::Array(items.iter().map(value_to_json).collect()),
        Value::Object(members) => Json::Object(
            members
                .iter()
                .map(|(key, value)| (key.clone(), value_to_json(value)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    fn fixture() -> Value {
        // A passing canary report, mirroring test-release-canary.py's fixture.
        let mut samples = String::from("[");
        for index in 0..24 {
            if index > 0 {
                samples.push(',');
            }
            let rss = 20_000 + (index % 4) * 64;
            let fd = 20 + (index % 5);
            let _ = write!(samples, "{{\"rssKiB\":{rss},\"fd\":{fd},\"threads\":4}}");
        }
        samples.push(']');
        let checks: String = REQUIRED_CHECKS
            .iter()
            .map(|name| format!("\"{name}\":true"))
            .collect::<Vec<_>>()
            .join(",");
        let text = format!(
            r#"{{
              "schemaVersion":1,
              "candidate":{{"commit":"{a}","sha256":"{b}","buildId":"{c}","version":"1.7.0","target":"x86_64-unknown-linux-gnu","rustc":"rustc 1.96.0"}},
              "comparator":{{"name":"Xray","version":"26.7.28","sha256":"{d}","buildId":"{e}"}},
              "elapsedSeconds":600,
              "checks":{{{checks}}},
              "traffic":{{"connectionsAttempted":1000,"connectionsSuccessful":999}},
              "handoffPool":{{"checkoutHit":995,"checkoutMiss":5,"coldFallback":5,"targetReadyPeak":64,"maxReady":128,"connectingPeak":24,"maxConnecting":32}},
              "landingRejections":{{"count":4,"authenticationOrProtocol":0}},
              "resources":{{"line":{samples},"landing":{samples}}}
            }}"#,
            a = "a".repeat(40),
            b = "b".repeat(64),
            c = "c".repeat(40),
            d = "d".repeat(64),
            e = "e".repeat(40),
        );
        json_in::parse(&text).expect("fixture parses")
    }

    #[test]
    fn a_healthy_canary_passes() {
        let (reasons, _, _) = evaluate(&fixture());
        assert!(reasons.is_empty(), "healthy canary must pass: {reasons:?}");
    }

    #[test]
    fn a_failed_reload_and_pool_and_fd_regression_is_caught() {
        let mut text = String::new();
        // Rebuild the fixture JSON, then mutate three fields the Python test flips.
        let base = fixture();
        // Re-serialize to text and patch: easier to construct a new bad report.
        let checks: String = REQUIRED_CHECKS
            .iter()
            .map(|name| {
                let value = if *name == "lineReload" { "false" } else { "true" };
                format!("\"{name}\":{value}")
            })
            .collect::<Vec<_>>()
            .join(",");
        // 24 samples; force the last sample's fd to 3000 to exceed the line peak.
        let mut samples = String::from("[");
        for index in 0..24 {
            if index > 0 {
                samples.push(',');
            }
            let fd = if index == 23 { 3000 } else { 20 + (index % 5) };
            let _ = write!(samples, "{{\"rssKiB\":20000,\"fd\":{fd},\"threads\":4}}");
        }
        samples.push(']');
        let _ = write!(text, 
            r#"{{
              "schemaVersion":1,
              "candidate":{{"commit":"{a}","sha256":"{b}","buildId":"{c}","version":"1.7.0","target":"t","rustc":"r"}},
              "comparator":{{"name":"Xray","version":"1","sha256":"{d}","buildId":"{e}"}},
              "elapsedSeconds":600,
              "checks":{{{checks}}},
              "traffic":{{"connectionsAttempted":1000,"connectionsSuccessful":999}},
              "handoffPool":{{"checkoutHit":995,"checkoutMiss":5,"coldFallback":5,"targetReadyPeak":64,"maxReady":128,"connectingPeak":33,"maxConnecting":32}},
              "landingRejections":{{"count":4,"authenticationOrProtocol":0}},
              "resources":{{"line":{samples},"landing":{samples}}}
            }}"#,
            a = "a".repeat(40), b = "b".repeat(64), c = "c".repeat(40), d = "d".repeat(64), e = "e".repeat(40),
        );
        let _ = base;
        let report = json_in::parse(&text).expect("bad fixture parses");
        let (reasons, _, _) = evaluate(&report);
        assert!(!reasons.is_empty());
        assert!(reasons.iter().any(|r| r.contains("lineReload")), "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("maxConnecting")), "{reasons:?}");
        assert!(reasons.iter().any(|r| r.contains("FD")), "{reasons:?}");
    }

    #[test]
    fn a_landing_authentication_rejection_is_caught() {
        let base = fixture();
        // Serialize the fixture back and flip landingRejections.
        let Value::Object(mut members) = base else {
            panic!("fixture is an object");
        };
        members.insert(
            "landingRejections".to_owned(),
            json_in::parse(r#"{"count":4,"authenticationOrProtocol":1}"#).unwrap(),
        );
        let report = Value::Object(members);
        let (reasons, _, _) = evaluate(&report);
        assert!(
            reasons.iter().any(|r| r.contains("authentication/protocol")),
            "{reasons:?}"
        );
    }
}
