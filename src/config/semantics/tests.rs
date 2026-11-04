use std::path::Path;

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};

use super::{ValidatedConfig, validate};
use crate::config::parse::parse_bytes;

/// A distinct, well-formed 32-byte key, so tests never collide by accident.
fn key(seed: u8) -> String {
    BASE64_URL_SAFE_NO_PAD.encode([seed; 32])
}

fn entry_json(body: &str) -> String {
    format!(
        r#"{{
              "role": "entry",
              "listeners": [{{ "port": 443 }}],
              "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
              "users": [{{ "id": "11111111-1111-4111-8111-111111111111",
                           "shortIds": ["ab"] }}],
              "routing": {{ "default": "direct" }}
              {body}
            }}"#,
        key(1)
    )
}

fn landing_json(body: &str) -> String {
    format!(
        r#"{{
              "role": "landing",
              "listeners": [{{ "port": 7443 }}],
              "landing": {{ "protocol": "handoff", "psk": "{}", "privateKey": "{}" }}
              {body}
            }}"#,
        key(2),
        key(3)
    )
}

fn check(json: &str) -> Result<ValidatedConfig, super::SemanticError> {
    let node = parse_bytes(Path::new("config.json"), json.as_bytes())
        .unwrap_or_else(|error| panic!("must parse before it can be validated: {error}"));
    validate(node)
}

fn accept(json: &str) -> ValidatedConfig {
    check(json).unwrap_or_else(|error| panic!("must validate: {error}"))
}

fn reject(json: &str) -> super::SemanticError {
    check(json).expect_err("must not validate")
}

// ------------------------------------------------------------- acceptance

#[test]
fn a_minimal_standalone_node_validates() {
    let validated = accept(&entry_json(""));

    assert_eq!(validated.role(), crate::config::node::Role::Entry);
}

#[test]
fn a_minimal_landing_validates() {
    accept(&landing_json(""));
}

#[test]
fn a_line_node_with_a_handoff_landing_validates() {
    accept(&format!(
        r#"{{
              "role": "entry",
              "listeners": [{{ "port": 443 }}],
              "reality": {{ "cover": "www.example.com:443", "privateKey": "{}" }},
              "users": [{{ "id": "11111111-1111-4111-8111-111111111111",
                           "shortIds": ["ab"], "policy": "split" }}],
              "outbounds": {{ "landing-1": {{ "type": "handoff", "address": "10.0.0.2",
                              "port": 7443, "psk": "{}", "landingPublicKey": "{}" }} }},
              "routing": {{
                "default": "landing-1",
                "rules": [{{ "ip": ["geoip:private"], "outbound": "block" }}],
                "policies": {{ "split": {{ "default": "landing-1",
                  "rules": [{{ "domain": ["geosite:cn"], "outbound": "direct" }}] }} }}
              }}
            }}"#,
        key(1),
        key(2),
        key(3)
    ));
}

// -------------------------------------------------------------- listeners

#[test]
fn two_listeners_may_share_a_family_but_not_a_socket() {
    accept(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}},{{"port":8443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
        key(1)
    ));

    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}},{{"port":443,"ip":"ipv4Only"}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
        key(1)
    ));
    assert_eq!(error.path(), "listeners[1].port");
    assert!(error.message().contains("already bound"), "{error}");
}

#[test]
fn port_zero_is_refused() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":0}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "listeners[0].port");
}

// ---------------------------------------------------------------- reality

#[test]
fn the_cover_must_carry_a_port() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "reality.cover");
    assert!(error.message().contains("host:port"), "{error}");
}

#[test]
fn a_malformed_private_key_states_the_rule_without_echoing_the_value() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct"}}}}"#,
        BASE64_URL_SAFE_NO_PAD.encode([9u8; 31])
    ));

    assert_eq!(error.path(), "reality.privateKey");
    assert!(error.message().contains("32 bytes"), "{error}");
    assert!(
        !error
            .message()
            .contains(&BASE64_URL_SAFE_NO_PAD.encode([9u8; 31])),
        "a diagnostic must never echo key material"
    );
}

#[test]
fn an_ip_cover_requires_explicit_server_names() {
    let ip_cover = |names: &str| {
        format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"93.184.216.34:443","privateKey":"{}"{names}}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "routing":{{"default":"direct"}}}}"#,
            key(1)
        )
    };

    let error = reject(&ip_cover(""));
    assert_eq!(error.path(), "reality.cover");
    assert!(error.message().contains("serverNames"), "{error}");

    accept(&ip_cover(r#","serverNames":["www.example.com"]"#));
}

#[test]
fn server_names_reject_unsafe_patterns_and_repeats() {
    let with_names = |names: &str| {
        format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}",
                                 "serverNames":{names}}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "routing":{{"default":"direct"}}}}"#,
            key(1)
        )
    };

    accept(&with_names(r#"["www.example.com","*.example.com"]"#));
    assert_eq!(
        reject(&with_names(r#"["*"]"#)).path(),
        "reality.serverNames[0]"
    );
    assert_eq!(reject(&with_names("[]")).path(), "reality.serverNames");
    let repeat = reject(&with_names(r#"["a.example.com","A.EXAMPLE.COM"]"#));
    assert_eq!(repeat.path(), "reality.serverNames[1]");
    assert!(repeat.message().contains("more than once"), "{repeat}");
}

// ------------------------------------------------------------------ users

#[test]
fn identities_and_short_ids_must_be_unique_across_the_node() {
    let users = |users: &str| {
        format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                     "users":{users},
                     "routing":{{"default":"direct"}}}}"#,
            key(1)
        )
    };

    let duplicate_identity = reject(&users(
        r#"[{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]},
                {"id":"11111111-1111-4111-8111-111111111111","shortIds":["cd"]}]"#,
    ));
    assert_eq!(duplicate_identity.path(), "users[1].id");

    let shared_short_id = reject(&users(
        r#"[{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]},
                {"id":"22222222-2222-4222-8222-222222222222","shortIds":["AB"]}]"#,
    ));
    assert_eq!(shared_short_id.path(), "users[1].shortIds[0]");
    assert!(
        shared_short_id.message().contains("another identity"),
        "{shared_short_id}"
    );

    assert_eq!(reject(&users("[]")).path(), "users");
    assert_eq!(
        reject(&users(r#"[{"id":"not-a-uuid","shortIds":["ab"]}]"#)).path(),
        "users[0].id"
    );
    assert_eq!(
        reject(&users(
            r#"[{"id":"11111111-1111-4111-8111-111111111111","shortIds":["abc"]}]"#
        ))
        .path(),
        "users[0].shortIds[0]"
    );
}

#[test]
fn a_user_policy_must_name_a_declared_policy() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111",
                            "shortIds":["ab"],"policy":"missing"}}],
                 "routing":{{"default":"direct"}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "users[0].policy");
    assert!(error.message().contains("missing"), "{error}");
}

// ---------------------------------------------------------------- routing

#[test]
fn every_outbound_reference_must_resolve_and_names_the_alternatives() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"nowhere"}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "routing.default");
    assert!(error.message().contains("nowhere"), "{error}");
    assert!(
        error.message().contains("direct") && error.message().contains("block"),
        "the message must list what does exist: {error}"
    );
}

#[test]
fn a_rule_without_a_condition_is_refused() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct",
                             "rules":[{{"outbound":"block"}}]}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "routing.rules[0]");
    assert!(error.message().contains("shadow"), "{error}");
}

#[test]
fn matchers_are_validated_inside_policies_too() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "routing":{{"default":"direct","policies":{{"p":{{"default":"direct",
                   "rules":[{{"ip":["10.0.0.0/99"],"outbound":"block"}}]}}}}}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "routing.policies.p.rules[0].ip[0]");
}

// -------------------------------------------------------------- outbounds

#[test]
fn a_built_in_name_cannot_be_redeclared() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "outbounds":{{"direct":{{"type":"socks5","address":"10.0.0.9","port":1080}}}},
                 "routing":{{"default":"direct"}}}}"#,
        key(1)
    ));

    assert_eq!(error.path(), "outbounds.direct");
    assert!(error.message().contains("built in"), "{error}");
}

#[test]
fn socks5_credentials_must_come_as_a_pair() {
    let socks = |credentials: &str| {
        format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "outbounds":{{"up":{{"type":"socks5","address":"10.0.0.9","port":1080{credentials}}}}},
                     "routing":{{"default":"up"}}}}"#,
            key(1)
        )
    };

    accept(&socks(""));
    accept(&socks(r#","username":"u","password":"p""#));
    assert_eq!(reject(&socks(r#","username":"u""#)).path(), "outbounds.up");
    assert_eq!(
        reject(&socks(r#","username":"","password":"p""#)).path(),
        "outbounds.up.username"
    );
}

#[test]
fn a_handoff_outbound_must_answer_after_it_connects() {
    let handoff = |timeouts: &str| {
        format!(
            r#"{{"role":"entry","listeners":[{{"port":443}}],
                     "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                     "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                     "outbounds":{{"l":{{"type":"handoff","address":"10.0.0.2","port":7443,
                       "psk":"{}","landingPublicKey":"{}"{timeouts}}}}},
                     "routing":{{"default":"l"}}}}"#,
            key(1),
            key(2),
            key(3)
        )
    };

    accept(&handoff(""));
    let error = reject(&handoff(
        r#","connectTimeoutMs":20000,"firstByteTimeoutMs":10000"#,
    ));
    assert_eq!(error.path(), "outbounds.l.firstByteTimeoutMs");
    assert!(
        error.message().contains("exceed connectTimeoutMs"),
        "{error}"
    );
}

// ---------------------------------------------------------------- landing

#[test]
fn a_landing_egress_may_not_chain_to_another_landing() {
    let error = reject(&format!(
        r#"{{"role":"landing","listeners":[{{"port":7443}}],
                 "landing":{{"protocol":"handoff","psk":"{}","privateKey":"{}"}},
                 "outbounds":{{"next":{{"type":"handoff","address":"10.0.0.3","port":7443,
                   "psk":"{}","landingPublicKey":"{}"}}}},
                 "egress":"next"}}"#,
        key(2),
        key(3),
        key(4),
        key(5)
    ));

    assert_eq!(error.path(), "egress");
    assert!(error.message().contains("another landing"), "{error}");
}

#[test]
fn an_unknown_egress_is_refused_and_direct_is_the_default() {
    accept(&landing_json(""));
    accept(&landing_json(r#","egress":"block""#));
    assert_eq!(
        reject(&landing_json(r#","egress":"nowhere""#)).path(),
        "egress"
    );
}

#[test]
fn a_rotation_window_is_bounded_and_may_not_relist_the_active_key() {
    let rotate = |previous: &str| {
        format!(
            r#"{{"role":"landing","listeners":[{{"port":7443}}],
                     "landing":{{"protocol":"handoff","psk":"{}","privateKey":"{}",
                                 "previousPsks":{previous}}}}}"#,
            key(2),
            key(3)
        )
    };

    accept(&rotate(&format!(r#"["{}"]"#, key(9))));
    accept(&rotate(&format!(r#"["{}","{}"]"#, key(9), key(10))));

    let too_many = reject(&rotate(&format!(
        r#"["{}","{}","{}"]"#,
        key(9),
        key(10),
        key(11)
    )));
    assert_eq!(too_many.path(), "landing.previousPsks");

    let active = reject(&rotate(&format!(r#"["{}"]"#, key(2))));
    assert_eq!(active.path(), "landing.previousPsks[0]");
    assert!(active.message().contains("active key"), "{active}");

    let repeat = reject(&rotate(&format!(r#"["{}","{}"]"#, key(9), key(9))));
    assert_eq!(repeat.path(), "landing.previousPsks[1]");
}

// ----------------------------------------------------------- key reuse

#[test]
fn two_values_may_not_carry_the_same_key_material() {
    let error = reject(&format!(
        r#"{{"role":"entry","listeners":[{{"port":443}}],
                 "reality":{{"cover":"www.example.com:443","privateKey":"{}"}},
                 "users":[{{"id":"11111111-1111-4111-8111-111111111111","shortIds":["ab"]}}],
                 "outbounds":{{"l":{{"type":"nxr","address":"10.0.0.2","port":7443,"psk":"{}"}}}},
                 "routing":{{"default":"l"}}}}"#,
        key(1),
        key(1)
    ));

    assert_eq!(error.path(), "outbounds.l.psk");
    assert!(error.message().contains("reality.privateKey"), "{error}");
    assert!(error.message().contains("independently"), "{error}");
}

#[test]
fn pasting_a_private_key_where_the_public_half_belongs_is_caught() {
    let error = reject(&format!(
        r#"{{"role":"landing","listeners":[{{"port":7443}}],
                 "landing":{{"protocol":"handoff","psk":"{}","privateKey":"{}"}},
                 "outbounds":{{"up":{{"type":"handoff","address":"10.0.0.3","port":7443,
                   "psk":"{}","landingPublicKey":"{}"}}}}}}"#,
        key(2),
        key(3),
        key(4),
        key(3)
    ));

    assert_eq!(error.path(), "outbounds.up.landingPublicKey");
    assert!(error.message().contains("landing.privateKey"), "{error}");
}

// ------------------------------------------------------------------- dns

#[test]
fn the_system_resolver_cannot_be_mixed_with_others() {
    let dns = |servers: &str| entry_json(&format!(r#","dns":{{"servers":{servers}}}"#));

    accept(&dns(r#"["system"]"#));
    accept(&dns(r#"["1.1.1.1","[2606:4700:4700::1111]:53"]"#));
    assert_eq!(
        reject(&dns(r#"["system","1.1.1.1"]"#)).path(),
        "dns.servers"
    );
    assert_eq!(reject(&dns("[]")).path(), "dns.servers");
}

#[test]
fn dns_cache_bounds_must_be_ordered() {
    let error = reject(&entry_json(
        r#","dns":{"cache":{"minTtlSeconds":100,"maxTtlSeconds":50}}"#,
    ));

    assert_eq!(error.path(), "dns.cache.minTtlSeconds");
}

// ------------------------------------------------------------------- log

#[test]
fn file_logging_and_the_file_block_imply_each_other() {
    assert_eq!(
        reject(&entry_json(r#","log":{"output":"file"}"#)).path(),
        "log.file"
    );
    assert_eq!(
        reject(&entry_json(
            r#","log":{"output":"stderr","file":{"path":"/var/log/rr.log"}}"#
        ))
        .path(),
        "log.file"
    );
    accept(&entry_json(
        r#","log":{"output":"file","file":{"path":"/var/log/rr.log"}}"#,
    ));
}

#[test]
fn log_rotation_bounds_are_checked() {
    assert_eq!(
        reject(&entry_json(
            r#","log":{"output":"file","file":{"path":"/var/log/rr.log","maxBytes":1024}}"#
        ))
        .path(),
        "log.file.maxBytes"
    );
    assert_eq!(
        reject(&entry_json(
            r#","log":{"output":"file","file":{"path":"/var/log/rr.log","maxTotalBytes":1024}}"#
        ))
        .path(),
        "log.file.maxTotalBytes"
    );
}

// --------------------------------------------------------------- runtime

#[test]
fn a_status_file_without_adaptive_tuning_is_refused() {
    assert_eq!(
        reject(&entry_json(r#","runtime":{"statusFile":"/run/rr.json"}"#)).path(),
        "runtime.statusFile"
    );
    accept(&entry_json(
        r#","runtime":{"tuning":"adaptive","statusFile":"/run/rr.json"}"#,
    ));
}

#[test]
fn pinned_limits_are_checked_against_each_other_only_when_both_are_pinned() {
    // Only one side pinned: the other derives, so the relation is settled
    // when the effective policy is compiled, not here.
    accept(&entry_json(
        r#","runtime":{"limits":{"maxHandshakes":100000}}"#,
    ));

    let error = reject(&entry_json(
        r#","runtime":{"limits":{"maxConnections":1024,"maxHandshakes":2048}}"#,
    ));
    assert_eq!(error.path(), "runtime.limits.maxHandshakes");

    let ordering = reject(&entry_json(
        r#","runtime":{"limits":{"clientHelloTimeoutMs":9000,"handshakeTimeoutMs":3000}}"#,
    ));
    assert_eq!(ordering.path(), "runtime.limits.clientHelloTimeoutMs");
}

#[test]
fn pooling_splice_pipes_requires_splice() {
    let error = reject(&entry_json(
        r#","runtime":{"limits":{"splice":false,"pipePool":true}}"#,
    ));

    assert_eq!(error.path(), "runtime.limits.pipePool");
}

#[test]
fn a_zero_limit_is_refused_rather_than_silently_disabling_the_server() {
    assert_eq!(
        reject(&entry_json(r#","runtime":{"limits":{"maxConnections":0}}"#)).path(),
        "runtime.limits.maxConnections"
    );
}

// ---------------------------------------------------------------- assets

#[test]
fn asset_sources_must_be_https() {
    assert_eq!(
        reject(&entry_json(
            r#","assets":{"geoip":"http://example.com/geoip.dat"}"#
        ))
        .path(),
        "assets.geoip"
    );
    accept(&entry_json(
        r#","assets":{"geoip":"https://example.com/geoip.dat"}"#,
    ));
}
