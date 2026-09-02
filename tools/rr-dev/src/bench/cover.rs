//! The REALITY cover path: optimisation modes and the counters that prove them.
//!
//! `benchmark-setup-rate.sh` exists to measure connection setup, and the dominant
//! cost in setup is reaching the *cover* target — the real TLS site a REALITY
//! server borrows its handshake from. Its cover modes are the independent variable:
//!
//! | mode       | what it isolates                                             |
//! |------------|--------------------------------------------------------------|
//! | `default`  | whatever each build does out of the box; no override at all   |
//! | `cold`     | a fresh cover connection per session (`warmTcp: false`)       |
//! | `warm`     | a pooled, pre-warmed cover connection (`warmTcp: true`)       |
//! | `prebuilt` | warm pooling *plus* pre-built `ClientHello` profiles            |
//!
//! ## The asymmetry is deliberate
//!
//! Under `cold` and `warm`, the candidate gets `prebuiltProfiles: false` while the
//! baseline gets no such key. That is not an oversight. The baseline is an older
//! ELF that does not understand the field, and the candidate does — so the
//! candidate must be told to switch it *off*, or `warmTcp` would not be the only
//! difference between the two sides and the comparison would measure two changes
//! at once. Under `prebuilt` both sides get the identical object, because there
//! the profile machinery is the thing being measured.
//!
//! ## Fail-closed counters
//!
//! A cover-pool run that reports no checkouts, or whose hits and misses do not add
//! up, has not demonstrated pooling — it has demonstrated a broken counter. The
//! same holds for the profile summary: a run that never validated a profile cannot
//! be evidence that pre-built profiles work. Both extractors refuse such a slot
//! rather than summarising it.

use crate::{
    bench::suites::render_compact,
    perf::{json_in, json_out::Json},
};

/// Which side of the comparison a slot is measuring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The pinned baseline ELF.
    Baseline,
    /// The candidate ELF under test.
    Candidate,
}

/// The cover-optimisation mode a run pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverMode {
    /// No override; each build uses its own default.
    Default,
    /// A fresh cover connection per session.
    Cold,
    /// A pooled, pre-warmed cover connection.
    Warm,
    /// Warm pooling plus pre-built `ClientHello` profiles.
    Prebuilt,
}

impl CoverMode {
    /// Parses the `BASELINE_COVER_MODE` / `CANDIDATE_COVER_MODE` spelling.
    ///
    /// # Errors
    ///
    /// Returns the script's own message for an unknown mode.
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "default" => Ok(Self::Default),
            "cold" => Ok(Self::Cold),
            "warm" => Ok(Self::Warm),
            "prebuilt" => Ok(Self::Prebuilt),
            other => Err(format!("unsupported cover mode: {other}")),
        }
    }

    /// The mode's name, as the environment recorded it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Cold => "cold",
            Self::Warm => "warm",
            Self::Prebuilt => "prebuilt",
        }
    }

    /// The `coverOptimization` object for `role`, or `None` to leave it unset.
    fn optimization(self, role: Role) -> Option<json_in::Value> {
        let object = |fields: Vec<(&str, json_in::Value)>| {
            json_in::Value::Object(
                fields
                    .into_iter()
                    .map(|(key, value)| (key.to_owned(), value))
                    .collect(),
            )
        };
        let flag = json_in::Value::Bool;
        match (self, role) {
            (Self::Default, _) => None,
            (Self::Cold, Role::Baseline) => Some(object(vec![
                ("enabled", flag(true)),
                ("warmTcp", flag(false)),
            ])),
            (Self::Cold, Role::Candidate) => Some(object(vec![
                ("enabled", flag(true)),
                ("warmTcp", flag(false)),
                ("prebuiltProfiles", flag(false)),
            ])),
            (Self::Warm, Role::Baseline) => Some(object(vec![
                ("enabled", flag(true)),
                ("warmTcp", flag(true)),
            ])),
            (Self::Warm, Role::Candidate) => Some(object(vec![
                ("enabled", flag(true)),
                ("warmTcp", flag(true)),
                ("prebuiltProfiles", flag(false)),
            ])),
            (Self::Prebuilt, _) => Some(object(vec![
                ("enabled", flag(true)),
                ("warmTcp", flag(true)),
                ("prebuiltProfiles", flag(true)),
            ])),
        }
    }
}

/// Applies a slot's cover mode and log level to a generated server config.
///
/// The log level rises to `info` whenever the netem cover leg is in play, because
/// that is the only way the `cover_pool_summary` and `cover_profile_summary`
/// records — which the run then requires — reach the log at all.
///
/// # Errors
///
/// Returns a message when the config is not the expected object shape.
pub fn apply(
    server_json: &str,
    mode: CoverMode,
    role: Role,
    netem_enabled: bool,
) -> Result<String, String> {
    let value = json_in::parse(server_json)
        .map_err(|error| format!("the generated server config is invalid JSON: {error}"))?;
    let json_in::Value::Object(mut members) = value else {
        return Err("the generated server config is not an object".to_owned());
    };

    let json_in::Value::Object(mut log) = members
        .get("log")
        .cloned()
        .unwrap_or_else(|| json_in::Value::Object(std::collections::BTreeMap::new()))
    else {
        return Err("the generated server config log is not an object".to_owned());
    };
    log.insert(
        "level".to_owned(),
        json_in::Value::Str(if netem_enabled { "info" } else { "warn" }.to_owned()),
    );
    members.insert("log".to_owned(), json_in::Value::Object(log));

    if let Some(optimization) = mode.optimization(role) {
        set_reality_field(&mut members, "coverOptimization", optimization)?;
    }
    Ok(render_compact(&json_in::Value::Object(members)))
}

/// Sets `inbounds[0].streamSettings.realitySettings.<key>`.
fn set_reality_field(
    members: &mut std::collections::BTreeMap<String, json_in::Value>,
    key: &str,
    value: json_in::Value,
) -> Result<(), String> {
    let Some(json_in::Value::Array(inbounds)) = members.get_mut("inbounds") else {
        return Err("the server config has no inbounds array".to_owned());
    };
    let Some(json_in::Value::Object(inbound)) = inbounds.first_mut() else {
        return Err("the server config has no inbounds[0] object".to_owned());
    };
    let Some(json_in::Value::Object(stream)) = inbound.get_mut("streamSettings") else {
        return Err("inbounds[0] has no streamSettings object".to_owned());
    };
    let Some(json_in::Value::Object(reality)) = stream.get_mut("realitySettings") else {
        return Err("streamSettings has no realitySettings object".to_owned());
    };
    reality.insert(key.to_owned(), value);
    Ok(())
}

/// The cover-pool checkout counters one slot reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSummary {
    /// Total checkouts from the cover pool.
    pub checkout_total: i64,
    /// Checkouts served by a warm pooled connection.
    pub checkout_hit: i64,
    /// Checkouts that had to build a connection.
    pub checkout_miss: i64,
    /// Checkouts that fell back to a cold path.
    pub cold_fallback: i64,
    /// Pooled connections discarded as stale.
    pub stale_discard: i64,
}

impl PoolSummary {
    /// The fraction of checkouts a warm connection served.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "checkout counts are far below 2^53"
    )]
    pub fn warm_hit_ratio(&self) -> f64 {
        self.checkout_hit as f64 / self.checkout_total as f64
    }
}

/// The cover-profile counters one slot reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileSummary {
    /// Sessions served from a cached profile.
    pub hit: i64,
    /// Sessions that had to build a profile.
    pub miss: i64,
    /// Profiles found stale.
    pub stale: i64,
    /// Profiles observed to be unstable.
    pub unstable: i64,
    /// Profile refreshes attempted.
    pub refresh: i64,
    /// Profile refreshes that failed.
    pub refresh_failure: i64,
    /// Differential-consensus disagreements.
    pub disagreement: i64,
    /// Profiles that passed validation.
    pub validated: i64,
}

impl ProfileSummary {
    /// The fraction of sessions a cached profile served.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "profile counts are far below 2^53"
    )]
    pub fn profile_hit_ratio(&self) -> f64 {
        self.hit as f64 / (self.hit + self.miss) as f64
    }
}

/// Finds the single record of `event` in a JSON-lines server log.
///
/// The originals required *exactly one*: zero means the server never emitted its
/// summary, and more than one means slots leaked into each other's log.
fn single_record(log: &str, event: &str) -> Result<json_in::Value, String> {
    let mut found: Vec<json_in::Value> = Vec::new();
    for line in log.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = json_in::parse(line) else {
            continue;
        };
        if matches!(value.field("record", "event"), Ok(json_in::Value::Str(name)) if name == event)
        {
            found.push(value);
        }
    }
    let [record] = found.as_slice() else {
        return Err(format!("expected one {event}, found {}", found.len()));
    };
    Ok(record.clone())
}

/// Reads a required integer counter from a log record.
fn counter(record: &json_in::Value, name: &str) -> Result<i64, String> {
    match record.field("record", name) {
        Ok(json_in::Value::Number(text)) => text
            .parse::<i64>()
            .map_err(|error| format!("{name} is not an integer: {error}")),
        _ => Err(format!("the record has no integer {name}")),
    }
}

/// Extracts and validates the cover-pool summary from a server log.
///
/// # Errors
///
/// Returns a message when the record is absent, duplicated, or incoherent.
pub fn extract_pool_summary(log: &str) -> Result<PoolSummary, String> {
    let record = single_record(log, "cover_pool_summary")?;
    let summary = PoolSummary {
        checkout_total: counter(&record, "pool_checkout_total")?,
        checkout_hit: counter(&record, "pool_checkout_hit")?,
        checkout_miss: counter(&record, "pool_checkout_miss")?,
        cold_fallback: counter(&record, "pool_cold_fallback")?,
        stale_discard: counter(&record, "pool_stale_discard")?,
    };
    if summary.checkout_total <= 0
        || summary.checkout_hit + summary.checkout_miss != summary.checkout_total
    {
        return Err("incoherent cover pool checkout counters".to_owned());
    }
    Ok(summary)
}

/// Extracts and validates the cover-profile summary from a server log.
///
/// # Errors
///
/// Returns a message when the record is absent, duplicated, never validated a
/// profile, or reports any instability, refresh failure or disagreement.
pub fn extract_profile_summary(log: &str) -> Result<ProfileSummary, String> {
    let record = single_record(log, "cover_profile_summary")?;
    let summary = ProfileSummary {
        hit: counter(&record, "cover_profile_hit")?,
        miss: counter(&record, "cover_profile_miss")?,
        stale: counter(&record, "cover_profile_stale")?,
        unstable: counter(&record, "cover_profile_unstable")?,
        refresh: counter(&record, "cover_profile_refresh")?,
        refresh_failure: counter(&record, "cover_profile_refresh_failure")?,
        disagreement: counter(&record, "cover_profile_disagreement")?,
        validated: counter(&record, "cover_profile_validated")?,
    };
    if summary.hit <= 0 || summary.validated <= 0 {
        return Err("candidate benchmark did not exercise a validated profile hit".to_owned());
    }
    let state = record
        .field("record", "cover_profile_state")
        .and_then(|field| field.as_str("cover_profile_state"))
        .map_err(|error| error.to_string())?;
    if state != "validated"
        || summary.unstable != 0
        || summary.refresh_failure != 0
        || summary.disagreement != 0
    {
        return Err("controlled cover-profile differential consensus failed".to_owned());
    }
    Ok(summary)
}

/// Aggregates the per-slot pool summaries, or `null` when none were collected.
#[must_use]
pub fn aggregate_pool(slots: &[PoolSummary]) -> Json {
    if slots.is_empty() {
        return Json::Null;
    }
    let sum = |pick: fn(&PoolSummary) -> i64| slots.iter().map(pick).sum::<i64>();
    let total = sum(|slot| slot.checkout_total);
    let hit = sum(|slot| slot.checkout_hit);
    #[expect(
        clippy::cast_precision_loss,
        reason = "checkout counts are far below 2^53"
    )]
    let ratio = hit as f64 / total as f64;
    Json::object([
        (
            "slotCount",
            Json::Int(i64::try_from(slots.len()).unwrap_or(i64::MAX)),
        ),
        ("checkoutTotal", Json::Int(total)),
        ("checkoutHit", Json::Int(hit)),
        ("checkoutMiss", Json::Int(sum(|slot| slot.checkout_miss))),
        ("coldFallback", Json::Int(sum(|slot| slot.cold_fallback))),
        ("staleDiscard", Json::Int(sum(|slot| slot.stale_discard))),
        ("warmHitRatio", Json::Float(ratio)),
    ])
}

/// Aggregates the per-slot profile summaries, or `null` when none were collected.
#[must_use]
pub fn aggregate_profile(slots: &[ProfileSummary]) -> Json {
    if slots.is_empty() {
        return Json::Null;
    }
    let sum = |pick: fn(&ProfileSummary) -> i64| slots.iter().map(pick).sum::<i64>();
    let hit = sum(|slot| slot.hit);
    let miss = sum(|slot| slot.miss);
    #[expect(
        clippy::cast_precision_loss,
        reason = "profile counts are far below 2^53"
    )]
    let ratio = hit as f64 / (hit + miss) as f64;
    Json::object([
        (
            "slotCount",
            Json::Int(i64::try_from(slots.len()).unwrap_or(i64::MAX)),
        ),
        ("hit", Json::Int(hit)),
        ("miss", Json::Int(miss)),
        ("stale", Json::Int(sum(|slot| slot.stale))),
        ("unstable", Json::Int(sum(|slot| slot.unstable))),
        ("refresh", Json::Int(sum(|slot| slot.refresh))),
        (
            "refreshFailure",
            Json::Int(sum(|slot| slot.refresh_failure)),
        ),
        ("disagreement", Json::Int(sum(|slot| slot.disagreement))),
        ("profileHitRatio", Json::Float(ratio)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"{"log":{"level":"warn"},"inbounds":[{"port":443,
        "streamSettings":{"network":"tcp","security":"reality",
        "realitySettings":{"target":"dl.google.com:443"}}}]}"#;

    #[test]
    fn the_cover_modes_parse_and_round_trip() {
        for name in ["default", "cold", "warm", "prebuilt"] {
            assert_eq!(CoverMode::parse(name).unwrap().as_str(), name);
        }
        assert_eq!(
            CoverMode::parse("hot").unwrap_err(),
            "unsupported cover mode: hot"
        );
    }

    /// The default mode must leave the config untouched apart from the log level:
    /// it is the "whatever each build does out of the box" arm.
    #[test]
    fn the_default_mode_sets_no_cover_optimization() {
        let patched = apply(CONFIG, CoverMode::Default, Role::Candidate, false).unwrap();
        assert!(!patched.contains("coverOptimization"));
        assert!(patched.contains(r#""level":"warn""#));
    }

    /// The candidate is told to switch pre-built profiles *off* under cold and
    /// warm, so `warmTcp` is the only difference between the two sides.
    #[test]
    fn cold_and_warm_disable_prebuilt_profiles_on_the_candidate_only() {
        let baseline = apply(CONFIG, CoverMode::Cold, Role::Baseline, false).unwrap();
        assert!(baseline.contains(r#""warmTcp":false"#));
        assert!(
            !baseline.contains("prebuiltProfiles"),
            "the baseline ELF does not understand the field"
        );

        let candidate = apply(CONFIG, CoverMode::Cold, Role::Candidate, false).unwrap();
        assert!(candidate.contains(r#""warmTcp":false"#));
        assert!(candidate.contains(r#""prebuiltProfiles":false"#));

        let baseline = apply(CONFIG, CoverMode::Warm, Role::Baseline, false).unwrap();
        assert!(baseline.contains(r#""warmTcp":true"#));
        assert!(!baseline.contains("prebuiltProfiles"));

        let candidate = apply(CONFIG, CoverMode::Warm, Role::Candidate, false).unwrap();
        assert!(candidate.contains(r#""warmTcp":true"#));
        assert!(candidate.contains(r#""prebuiltProfiles":false"#));
    }

    /// Under `prebuilt` both sides get the identical object, because there the
    /// profile machinery is the thing being measured.
    #[test]
    fn prebuilt_configures_both_sides_identically() {
        let baseline = apply(CONFIG, CoverMode::Prebuilt, Role::Baseline, false).unwrap();
        let candidate = apply(CONFIG, CoverMode::Prebuilt, Role::Candidate, false).unwrap();
        assert_eq!(baseline, candidate);
        assert!(baseline.contains(r#""prebuiltProfiles":true"#));
        assert!(baseline.contains(r#""warmTcp":true"#));
    }

    /// The netem leg needs `info`, because that is the only level at which the
    /// pool and profile summaries the run then requires are emitted at all.
    #[test]
    fn the_netem_leg_raises_the_log_level_to_info() {
        let quiet = apply(CONFIG, CoverMode::Warm, Role::Candidate, false).unwrap();
        assert!(quiet.contains(r#""level":"warn""#));
        let loud = apply(CONFIG, CoverMode::Warm, Role::Candidate, true).unwrap();
        assert!(loud.contains(r#""level":"info""#));
    }

    #[test]
    fn a_malformed_config_fails_closed() {
        assert!(apply("not json", CoverMode::Warm, Role::Baseline, false).is_err());
        assert!(apply("[]", CoverMode::Warm, Role::Baseline, false).is_err());
        assert!(
            apply(
                r#"{"log":{},"inbounds":[]}"#,
                CoverMode::Warm,
                Role::Baseline,
                false
            )
            .is_err()
        );
        // The default mode never touches realitySettings, so it tolerates a config
        // the other modes would reject.
        assert!(apply(r#"{"log":{}}"#, CoverMode::Default, Role::Baseline, false).is_ok());
    }

    fn pool_line(total: i64, hit: i64, miss: i64) -> String {
        format!(
            r#"{{"event":"cover_pool_summary","pool_checkout_total":{total},
               "pool_checkout_hit":{hit},"pool_checkout_miss":{miss},
               "pool_cold_fallback":1,"pool_stale_discard":2}}"#
        )
        .replace('\n', "")
    }

    #[test]
    fn a_coherent_pool_summary_is_accepted() {
        let log = format!("warming up\n{}\n", pool_line(100, 90, 10));
        let summary = extract_pool_summary(&log).unwrap();
        assert_eq!(summary.checkout_total, 100);
        assert_eq!(summary.checkout_hit, 90);
        assert!((summary.warm_hit_ratio() - 0.9).abs() < 1e-12);
    }

    /// Counters that do not add up have not demonstrated pooling; they have
    /// demonstrated a broken counter.
    #[test]
    fn an_incoherent_pool_summary_is_refused() {
        let log = pool_line(100, 90, 5);
        assert_eq!(
            extract_pool_summary(&log).unwrap_err(),
            "incoherent cover pool checkout counters"
        );
        let log = pool_line(0, 0, 0);
        assert_eq!(
            extract_pool_summary(&log).unwrap_err(),
            "incoherent cover pool checkout counters"
        );
    }

    #[test]
    fn a_missing_or_duplicated_pool_summary_is_refused() {
        assert!(
            extract_pool_summary("no records here")
                .unwrap_err()
                .contains("found 0")
        );
        let log = format!("{}\n{}\n", pool_line(10, 10, 0), pool_line(20, 20, 0));
        assert!(extract_pool_summary(&log).unwrap_err().contains("found 2"));
    }

    fn profile_line(hit: i64, validated: i64, state: &str, unstable: i64) -> String {
        format!(
            r#"{{"event":"cover_profile_summary","cover_profile_hit":{hit},
               "cover_profile_miss":4,"cover_profile_stale":0,
               "cover_profile_unstable":{unstable},"cover_profile_refresh":1,
               "cover_profile_refresh_failure":0,"cover_profile_disagreement":0,
               "cover_profile_validated":{validated},"cover_profile_state":"{state}"}}"#
        )
        .replace('\n', "")
    }

    #[test]
    fn a_validated_profile_summary_is_accepted() {
        let summary = extract_profile_summary(&profile_line(16, 4, "validated", 0)).unwrap();
        assert_eq!(summary.hit, 16);
        assert!((summary.profile_hit_ratio() - 0.8).abs() < 1e-12);
    }

    /// A run that never validated a profile cannot be evidence that pre-built
    /// profiles work.
    #[test]
    fn an_unvalidated_or_unstable_profile_summary_is_refused() {
        assert!(
            extract_profile_summary(&profile_line(0, 4, "validated", 0))
                .unwrap_err()
                .contains("validated profile hit")
        );
        assert!(
            extract_profile_summary(&profile_line(16, 0, "validated", 0))
                .unwrap_err()
                .contains("validated profile hit")
        );
        assert!(
            extract_profile_summary(&profile_line(16, 4, "unstable", 0))
                .unwrap_err()
                .contains("differential consensus failed")
        );
        assert!(
            extract_profile_summary(&profile_line(16, 4, "validated", 1))
                .unwrap_err()
                .contains("differential consensus failed")
        );
    }

    #[test]
    fn the_aggregates_match_the_legacy_shape() {
        let pools = vec![
            PoolSummary {
                checkout_total: 100,
                checkout_hit: 90,
                checkout_miss: 10,
                cold_fallback: 1,
                stale_discard: 2,
            },
            PoolSummary {
                checkout_total: 100,
                checkout_hit: 70,
                checkout_miss: 30,
                cold_fallback: 3,
                stale_discard: 4,
            },
        ];
        let rendered = aggregate_pool(&pools).to_python_json();
        assert!(rendered.contains("\"slotCount\": 2"));
        assert!(rendered.contains("\"checkoutTotal\": 200"));
        assert!(rendered.contains("\"checkoutHit\": 160"));
        assert!(rendered.contains("\"coldFallback\": 4"));
        assert!(rendered.contains("\"staleDiscard\": 6"));
        assert!(rendered.contains("\"warmHitRatio\": 0.8"));

        // No slots collected the counters at all, so there is nothing to claim.
        assert_eq!(aggregate_pool(&[]), Json::Null);
        assert_eq!(aggregate_profile(&[]), Json::Null);

        let profiles = vec![ProfileSummary {
            hit: 16,
            miss: 4,
            stale: 0,
            unstable: 0,
            refresh: 1,
            refresh_failure: 0,
            disagreement: 0,
            validated: 4,
        }];
        let rendered = aggregate_profile(&profiles).to_python_json();
        assert!(rendered.contains("\"hit\": 16"));
        assert!(rendered.contains("\"profileHitRatio\": 0.8"));
        assert!(rendered.contains("\"refreshFailure\": 0"));
    }
}
