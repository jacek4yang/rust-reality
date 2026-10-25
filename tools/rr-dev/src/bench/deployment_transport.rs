//! Transport / landing JSON mutation helpers for the deployment suite.
//!
//! Topology and RTT sections share these pure config rewrites. Keeping them
//! beside `deployment.rs` lets orchestration stay focused on `RunState` while
//! the listener/outbound port mutations remain independently reviewable.

use std::{collections::BTreeMap, path::Path};

use crate::{
    bench::{
        config::{self, RealityIdentity},
        soak,
    },
    perf::json_in::Value,
};

use super::deployment_json::{number, root_object, string};
use super::suites;

pub(crate) fn line_spec(
    line_port: u16,
    cover_port: u16,
    landing_port: u16,
    key: &str,
) -> soak::PublicNodeSpec {
    line_spec_to(line_port, cover_port, "127.0.0.1", landing_port, key)
}

pub(crate) fn line_spec_to(
    line_port: u16,
    cover_port: u16,
    peer_address: &str,
    peer_port: u16,
    key: &str,
) -> soak::PublicNodeSpec {
    soak::PublicNodeSpec::line(
        line_port,
        &format!("127.0.0.1:{cover_port}"),
        config::LandingLink {
            protocol: "nxr",
            address: peer_address.to_owned(),
            port: peer_port,
            psk: key.to_owned(),
            landing_public_key: None,
        },
    )
}

pub(crate) fn landing_config(port: u16, key: &str, level: &str) -> Result<String, String> {
    landing_config_at("127.0.0.1", port, key, level)
}

pub(crate) fn landing_config_at(
    listen: &str,
    port: u16,
    key: &str,
    level: &str,
) -> Result<String, String> {
    let rendered = config::rust_landing(
        listen,
        port,
        &config::LandingLink {
            protocol: "nxr",
            address: listen.to_owned(),
            port,
            psk: key.to_owned(),
            landing_public_key: None,
        },
        None,
    )
    .to_python_json();
    suites::set_rust_log_level(&rendered, level)
}

#[expect(
    clippy::too_many_arguments,
    reason = "a transport variant's exact endpoint and sole warm/cold difference stay explicit"
)]
pub(crate) fn transport_line_config(
    raw: &str,
    inbound_port: u16,
    protocol: &str,
    address: &str,
    outbound_port: u16,
    warm_tcp: bool,
    log_level: &str,
    cache: &Path,
) -> Result<String, String> {
    let mut root = root_object(raw)?;
    let Some(Value::Object(log)) = root.get_mut("log") else {
        return Err("generated transport config has no log object".to_owned());
    };
    log.insert("level".to_owned(), string(log_level));
    let Some(Value::Object(assets)) = root.get_mut("assets") else {
        return Err("generated transport config has no assets object".to_owned());
    };
    assets.insert(
        "cacheDirectory".to_owned(),
        string(cache.display().to_string()),
    );
    replace_listener_port(&mut root, inbound_port)?;
    let Some(Value::Object(outbounds)) = root.get_mut("outbounds") else {
        return Err("generated transport config has no outbounds object".to_owned());
    };
    let outbound = outbounds
        .values_mut()
        .find(|outbound| outbound.str_field("outbound", "type") == Ok(protocol))
        .ok_or_else(|| format!("generated transport config has no {protocol} outbound"))?;
    let Value::Object(outbound) = outbound else {
        unreachable!("the type lookup only matches outbound objects")
    };
    outbound.insert("address".to_owned(), string(address));
    outbound.insert("port".to_owned(), number(u64::from(outbound_port)));
    outbound.insert("warmTcp".to_owned(), Value::Bool(warm_tcp));
    Ok(suites::render_compact(&Value::Object(root)))
}

pub(crate) fn replace_listener_port(
    root: &mut BTreeMap<String, Value>,
    port: u16,
) -> Result<(), String> {
    let Some(Value::Array(listeners)) = root.get_mut("listeners") else {
        return Err("generated transport config has no listeners array".to_owned());
    };
    let [Value::Object(listener)] = listeners.as_mut_slice() else {
        return Err("generated transport config must have exactly one listener object".to_owned());
    };
    listener.insert("port".to_owned(), number(u64::from(port)));
    Ok(())
}

pub(crate) fn landing_variant_config(raw: &str, inbound_port: u16) -> Result<String, String> {
    let mut root = root_object(raw)?;
    // Current landing nodes have no entry-side asset cache.
    replace_listener_port(&mut root, inbound_port)?;
    Ok(suites::render_compact(&Value::Object(root)))
}

pub(crate) fn xray_client_ports(
    raw: &str,
    server_port: u16,
    socks_port: u16,
) -> Result<String, String> {
    let mut root = root_object(raw)?;
    let Some(Value::Array(inbounds)) = root.get_mut("inbounds") else {
        return Err("generated Xray client has no inbounds array".to_owned());
    };
    let Some(Value::Object(inbound)) = inbounds.first_mut() else {
        return Err("generated Xray client has no first inbound".to_owned());
    };
    inbound.insert("port".to_owned(), number(u64::from(socks_port)));
    let Some(Value::Array(outbounds)) = root.get_mut("outbounds") else {
        return Err("generated Xray client has no outbounds array".to_owned());
    };
    let Some(Value::Object(outbound)) = outbounds.first_mut() else {
        return Err("generated Xray client has no first outbound".to_owned());
    };
    let Some(Value::Object(settings)) = outbound.get_mut("settings") else {
        return Err("generated Xray client outbound has no settings".to_owned());
    };
    let Some(Value::Array(servers)) = settings.get_mut("vnext") else {
        return Err("generated Xray client has no vnext array".to_owned());
    };
    let Some(Value::Object(server)) = servers.first_mut() else {
        return Err("generated Xray client has no first vnext server".to_owned());
    };
    server.insert("port".to_owned(), number(u64::from(server_port)));
    Ok(suites::render_compact(&Value::Object(root)))
}

pub(crate) fn identity_for(
    generated: &soak::GeneratedPublicConfig,
    cover_port: u16,
) -> RealityIdentity {
    RealityIdentity {
        uuid: generated.uuid.clone(),
        short_id: generated.short_id.clone(),
        server_name: "localhost".to_owned(),
        target: format!("127.0.0.1:{cover_port}"),
    }
}
