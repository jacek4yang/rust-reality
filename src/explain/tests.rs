use super::{EXPLAIN_SCHEMA_VERSION, explain_config};
use crate::runtime::machine::MachineReport;

fn report() -> MachineReport {
    MachineReport {
        fd_soft_limit: 65_536,
        fd_hard_limit: 1_048_576,
        memlock_soft_limit: 0,
        memlock_hard_limit: 0,
        available_cpus: 4,
        cpu_quota_us: Some(400_000),
        cpu_period_us: Some(100_000),
        cpuset_effective: None,
        memory_source: "cgroup_v2",
        memory_current: None,
        memory_high: None,
        memory_max: Some(4 * 1024 * 1024 * 1024),
        memory_total: 4 * 1024 * 1024 * 1024,
    }
}

fn config() -> crate::config::NodeConfig {
    crate::config::node::fixture::entry().into_node()
}

#[test]
fn the_explain_report_schema_is_stable() {
    let explanation = explain_config(&config(), &report());
    let json = serde_json::to_value(&explanation).expect("the report must serialize");
    assert_eq!(json["schemaVersion"], EXPLAIN_SCHEMA_VERSION);
    assert_eq!(json["machine"]["effectiveCpus"], 4);
    assert_eq!(json["machine"]["fdSoftLimit"], 65_536);
    assert_eq!(
        json["machine"]["tenancyBoundaryObservable"], true,
        "a finite quota and memory.max make the boundary observable"
    );
    assert_eq!(json["profile"], "auto");
    assert_eq!(json["resolvedResourceMode"], "dedicated");
    assert_eq!(json["tuningMode"], "startup");
    assert_eq!(json["objective"], "balanced");
    assert_eq!(json["bootstrap"]["workerThreads"], 4);
    assert_eq!(json["bootstrap"]["maxBlockingThreads"], 64);
    assert_eq!(json["bootstrap"]["sizing"], "dedicated");
    let fields = json["fields"].as_array().expect("fields must be a list");
    assert_eq!(fields.len(), 25, "every policy field is explained");
    let connections = fields
        .iter()
        .find(|field| field["field"] == "governor.maxConnections")
        .expect("maxConnections is explained");
    assert_eq!(connections["source"], "startup-derived");
    assert_eq!(connections["multiplier"], 1.0);
    assert_eq!(connections["floor"], 64);
    let timeouts = fields
        .iter()
        .find(|field| field["field"] == "governor.handshakeTimeoutMs")
        .expect("timeouts are explained");
    assert!(
        timeouts.get("multiplier").is_none(),
        "timeouts carry no objective multiplier"
    );
    assert!(json["advisories"].is_array());
}

#[test]
fn the_explain_report_marks_operator_pins() {
    let config =
        crate::config::node::fixture::validated(&crate::config::node::fixture::entry_with(
            r#","runtime":{"profile":"shared","limits":{"maxConnections":100000}}"#,
        ))
        .into_node();
    let explanation = explain_config(&config, &report());
    let json = serde_json::to_value(&explanation).expect("the report must serialize");
    assert_eq!(json["resolvedResourceMode"], "standard");
    assert_eq!(json["bootstrap"]["sizing"], "tokio-default");
    assert_eq!(json["bootstrap"]["maxBlockingThreads"], 512);
    let fields = json["fields"].as_array().expect("fields must be a list");
    let pinned = fields
        .iter()
        .find(|field| field["field"] == "governor.maxConnections")
        .expect("maxConnections is explained");
    assert_eq!(pinned["value"], 100_000);
    assert_eq!(
        pinned["source"], "operator-pinned",
        "there is one override channel, and presence in it is the whole signal"
    );
    let derived = fields
        .iter()
        .find(|field| field["field"] == "governor.maxHandshakes")
        .expect("maxHandshakes is explained");
    assert_eq!(derived["source"], "startup-derived");
}

#[test]
fn the_human_summary_reports_decisions_not_the_field_table() {
    let explanation = explain_config(&config(), &report());
    let rendered = explanation.to_string();

    // The questions an operator asks.
    assert!(rendered.contains("role: entry"), "{rendered}");
    assert!(rendered.contains("listeners:"), "{rendered}");
    assert!(rendered.contains("0.0.0.0:443"), "{rendered}");
    assert!(rendered.contains("routing:"), "{rendered}");
    assert!(rendered.contains("default: direct"), "{rendered}");
    assert!(rendered.contains("outbounds: direct, block"), "{rendered}");
    assert!(rendered.contains("posture:"), "{rendered}");

    // Not the twenty-five-line policy table: that is `--json`.
    assert!(
        rendered.contains("all derived from the machine"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("relay.maxPooledBuffers"),
        "an unpinned derived field must not be listed: {rendered}"
    );
    assert!(
        rendered.lines().count() < 20,
        "the summary must stay readable, got {} lines:\n{rendered}",
        rendered.lines().count()
    );
}

#[test]
fn the_human_summary_lists_exactly_what_the_operator_pinned() {
    let config =
        crate::config::node::fixture::validated(&crate::config::node::fixture::entry_with(
            r#","runtime":{"limits":{"maxConnections":100000,"splice":false}}"#,
        ))
        .into_node();
    let rendered = explain_config(&config, &report()).to_string();

    assert!(rendered.contains("limits: 2 pinned"), "{rendered}");
    assert!(
        rendered.contains("governor.maxConnections = 100000"),
        "{rendered}"
    );
    assert!(rendered.contains("relay.splice = 0"), "{rendered}");
    assert!(
        !rendered.contains("governor.maxHandshakes"),
        "a derived sibling must not be listed: {rendered}"
    );
}

#[test]
fn a_route_query_names_the_rule_that_selected_the_outbound() {
    let config = crate::config::node::fixture::validated(
        &crate::config::node::fixture::entry_without_routing(
            r#""listeners": [{ "port": 443 }],
  "routing": { "default": "direct",
    "rules": [{ "name": "block-private", "ip": ["10.0.0.0/8"], "outbound": "block" }] }"#,
        ),
    )
    .into_node();

    let blocked = super::explain_route(&config, "10.1.2.3:443").expect("the query must answer");
    assert_eq!(blocked.outbound, "block");
    assert_eq!(blocked.matched, "block-private");
    assert_eq!(blocked.scope, "global rule");
    assert!(
        blocked.caveat.is_none(),
        "a configuration with no geo condition needs no caveat"
    );

    let defaulted = super::explain_route(&config, "example.com").expect("the query must answer");
    assert_eq!(defaulted.outbound, "direct");
    assert_eq!(defaulted.scope, "default outbound");
}

#[test]
fn a_route_query_says_when_it_could_not_evaluate_geo_rules() {
    let config = crate::config::node::fixture::validated(
        &crate::config::node::fixture::entry_without_routing(
            r#""listeners": [{ "port": 443 }],
  "routing": { "default": "direct",
    "rules": [{ "name": "cn", "domain": ["geosite:cn"], "outbound": "block" }] }"#,
        ),
    )
    .into_node();

    let answer = super::explain_route(&config, "www.example.cn").expect("the query must answer");

    assert_eq!(
        answer.outbound, "direct",
        "an unevaluated geo rule must not match"
    );
    let caveat = answer
        .caveat
        .expect("the answer must state what it skipped");
    assert!(caveat.contains("geosite:"), "{caveat}");
    assert!(caveat.contains("doctor"), "{caveat}");
}

#[test]
fn a_landing_node_has_no_route_to_explain() {
    let config =
        crate::config::node::fixture::validated(&crate::config::node::fixture::landing_json())
            .into_node();

    let error =
        super::explain_route(&config, "example.com").expect_err("a landing node does not route");

    assert!(matches!(error, super::RouteQueryError::NotAnEntryNode));
    assert!(error.to_string().contains("egress"), "{error}");
}

#[test]
fn destinations_parse_with_and_without_a_port() {
    use super::split_destination;

    assert_eq!(split_destination("example.com"), Some(("example.com", 443)));
    assert_eq!(
        split_destination("example.com:8443"),
        Some(("example.com", 8443))
    );
    assert_eq!(split_destination("10.0.0.1:80"), Some(("10.0.0.1", 80)));
    assert_eq!(split_destination("2001:db8::1"), Some(("2001:db8::1", 443)));
    assert_eq!(
        split_destination("[2001:db8::1]:8443"),
        Some(("2001:db8::1", 8443))
    );
    assert_eq!(
        split_destination("[2001:db8::1]"),
        Some(("2001:db8::1", 443))
    );
    assert_eq!(split_destination(""), None);
    assert_eq!(split_destination("example.com:notaport"), None);
}
