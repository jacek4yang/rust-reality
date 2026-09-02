#![no_main]

use arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::config::fuzz_load;
use serde_json::{Map, Value, json};

// Structured configuration target. A small custom generator builds JSON shaped
// like the real node grammar — every value is synthetic, never a real key,
// UUID, or capture — then a byte-level tail mutation keeps lexer-level rejects
// reachable. One input in sixteen bypasses the generator entirely and fuzzes
// raw bytes.
//
// The generator has to produce *nearly* valid documents most of the time, or
// everything fails at the role dispatch and the interesting rejects — key
// decoding, reference resolution, bound checks, key reuse — are never reached.

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_:/";
const BASE64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn gen_text(u: &mut Unstructured<'_>, maximum: usize) -> Result<String> {
    let length = u.int_in_range(0..=maximum)?;
    let mut text = String::with_capacity(length);
    for _ in 0..length {
        text.push(char::from(*u.choose(ALPHABET)?));
    }
    Ok(text)
}

fn gen_pick(u: &mut Unstructured<'_>, choices: &[&str]) -> Result<String> {
    if u.ratio(3, 4)? {
        Ok((*u.choose(choices)?).to_owned())
    } else {
        // Short garbage keeps enum and validation rejects reachable.
        gen_text(u, 8)
    }
}

/// A synthetic base64url string of a chosen length; never real key material.
fn gen_key(u: &mut Unstructured<'_>) -> Result<String> {
    // 43 characters is exactly 32 bytes; the neighbours exercise the length
    // rejection, and the alphabet break exercises the decode rejection.
    let length = *u.choose(&[0_usize, 42, 43, 44])?;
    let mut text = String::with_capacity(length);
    for _ in 0..length {
        text.push(char::from(*u.choose(BASE64URL)?));
    }
    if u.ratio(1, 8)? {
        text.push('!');
    }
    Ok(text)
}

fn gen_hex(u: &mut Unstructured<'_>, length: usize) -> Result<String> {
    let mut text = String::with_capacity(length);
    for _ in 0..length {
        text.push(char::from(*u.choose(b"0123456789abcdef")?));
    }
    Ok(text)
}

fn gen_u64(u: &mut Unstructured<'_>) -> Result<u64> {
    Ok(*u.choose(&[0_u64, 1, 2, 255, 4096, 65_535, 65_536, u64::from(u32::MAX)])?)
}

fn gen_port(u: &mut Unstructured<'_>) -> Result<u16> {
    Ok(*u.choose(&[0_u16, 1, 80, 443, 1080, 7443, 8080, 65_535])?)
}

fn gen_outbound_name(u: &mut Unstructured<'_>) -> Result<String> {
    if u.ratio(3, 4)? {
        Ok((*u.choose(&["direct", "block", "landing-1", "up"])?).to_owned())
    } else {
        gen_text(u, 12)
    }
}

fn gen_listeners(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut listeners = Vec::new();
    for _ in 0..u.int_in_range(0..=2_usize)? {
        let mut listener = Map::new();
        listener.insert("port".into(), json!(gen_port(u)?));
        if u.ratio(1, 2)? {
            listener.insert(
                "ip".into(),
                json!(gen_pick(u, &["auto", "dualStack", "ipv4Only", "ipv6Only"])?),
            );
        }
        listeners.push(Value::Object(listener));
    }
    Ok(Value::Array(listeners))
}

fn gen_log(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut log = Map::new();
    if u.ratio(3, 4)? {
        log.insert(
            "level".into(),
            json!(gen_pick(u, &["error", "warn", "info", "debug"])?),
        );
    }
    if u.ratio(3, 4)? {
        log.insert(
            "output".into(),
            json!(gen_pick(u, &["stderr", "journald", "file", "none"])?),
        );
    }
    if u.ratio(1, 4)? {
        log.insert(
            "file".into(),
            json!({
                "path": format!("/tmp/{}.log", gen_text(u, 8)?),
                "maxBytes": gen_u64(u)?,
                "maxFiles": gen_u64(u)?,
                "maxTotalBytes": gen_u64(u)?,
            }),
        );
    }
    Ok(Value::Object(log))
}

fn gen_dns(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut dns = Map::new();
    if u.ratio(3, 4)? {
        let mut servers = Vec::new();
        for _ in 0..u.int_in_range(0..=3_usize)? {
            servers.push(json!(gen_pick(
                u,
                &["system", "8.8.8.8", "1.1.1.1:53", "resolver.example"],
            )?));
        }
        dns.insert("servers".into(), Value::Array(servers));
    }
    if u.ratio(1, 3)? {
        dns.insert("timeoutMs".into(), json!(gen_u64(u)?));
    }
    if u.ratio(1, 4)? {
        dns.insert(
            "cache".into(),
            json!({
                "maxEntries": gen_u64(u)?,
                "minTtlSeconds": gen_u64(u)?,
                "maxTtlSeconds": gen_u64(u)?,
                "systemReuseMs": gen_u64(u)?,
            }),
        );
    }
    Ok(Value::Object(dns))
}

fn gen_user(u: &mut Unstructured<'_>) -> Result<Value> {
    // RFC 4122 version-4-shaped synthetic UUID; never a real subscriber UUID.
    let synthetic_uuid = format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        u.arbitrary::<u32>()?,
        u.arbitrary::<u16>()?,
        u.int_in_range(0..=0x0fff_u16)?,
        u.int_in_range(0..=0x0fff_u16)?,
        u.arbitrary::<u64>()? & 0xffff_ffff_ffff,
    );
    let mut short_ids = Vec::new();
    for _ in 0..u.int_in_range(0..=3_usize)? {
        let length = *u.choose(&[0_usize, 2, 3, 8, 16, 17])?;
        short_ids.push(json!(gen_hex(u, length)?));
    }
    let mut user = Map::new();
    user.insert(
        "id".into(),
        json!(if u.ratio(4, 5)? {
            synthetic_uuid
        } else {
            gen_text(u, 16)?
        }),
    );
    user.insert("shortIds".into(), Value::Array(short_ids));
    if u.ratio(1, 3)? {
        user.insert("label".into(), json!(gen_text(u, 10)?));
    }
    if u.ratio(1, 3)? {
        user.insert("policy".into(), json!(gen_pick(u, &["split", "missing"])?));
    }
    Ok(Value::Object(user))
}

fn gen_outbound(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut outbound = Map::new();
    let kind = gen_pick(u, &["socks5", "nxr", "handoff"])?;
    outbound.insert("type".into(), json!(kind.clone()));
    outbound.insert("address".into(), json!(gen_pick(u, &["10.0.0.2", "a.example", "-bad-"])?));
    outbound.insert("port".into(), json!(gen_port(u)?));
    match kind.as_str() {
        "socks5" => {
            if u.ratio(1, 3)? {
                outbound.insert("username".into(), json!(gen_text(u, 8)?));
            }
            if u.ratio(1, 3)? {
                outbound.insert("password".into(), json!(gen_text(u, 8)?));
            }
        }
        "nxr" => {
            outbound.insert("psk".into(), json!(gen_key(u)?));
        }
        _ => {
            outbound.insert("psk".into(), json!(gen_key(u)?));
            outbound.insert("landingPublicKey".into(), json!(gen_key(u)?));
            if u.ratio(1, 3)? {
                outbound.insert("connectTimeoutMs".into(), json!(gen_u64(u)?));
                outbound.insert("firstByteTimeoutMs".into(), json!(gen_u64(u)?));
            }
        }
    }
    Ok(Value::Object(outbound))
}

fn gen_rule(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut rule = Map::new();
    if u.ratio(1, 2)? {
        rule.insert("name".into(), json!(gen_text(u, 8)?));
    }
    if u.ratio(2, 3)? {
        rule.insert(
            "ip".into(),
            json!([gen_pick(u, &["geoip:private", "10.0.0.0/8", "10.0.0.0/99"])?]),
        );
    }
    if u.ratio(2, 3)? {
        rule.insert(
            "domain".into(),
            json!([gen_pick(
                u,
                &["geosite:cn", "full:example.com", "regexp:^a", "ext:x:y"]
            )?]),
        );
    }
    if u.ratio(1, 3)? {
        rule.insert(
            "port".into(),
            json!([gen_pick(u, &["443", "1-1024", "443-80", "0"])?]),
        );
    }
    rule.insert("outbound".into(), json!(gen_outbound_name(u)?));
    Ok(Value::Object(rule))
}

fn gen_routing(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut routing = Map::new();
    routing.insert("default".into(), json!(gen_outbound_name(u)?));
    if u.ratio(1, 2)? {
        routing.insert(
            "strategy".into(),
            json!(gen_pick(
                u,
                &["asIs", "resolveIfNoMatch", "resolveOnDemand"]
            )?),
        );
    }
    if u.ratio(3, 4)? {
        let mut rules = Vec::new();
        for _ in 0..u.int_in_range(0..=3_usize)? {
            rules.push(gen_rule(u)?);
        }
        routing.insert("rules".into(), Value::Array(rules));
    }
    if u.ratio(1, 3)? {
        let mut policy = Map::new();
        policy.insert("default".into(), json!(gen_outbound_name(u)?));
        policy.insert("rules".into(), json!([gen_rule(u)?]));
        routing.insert("policies".into(), json!({ "split": Value::Object(policy) }));
    }
    Ok(Value::Object(routing))
}

fn gen_entry(u: &mut Unstructured<'_>) -> Result<Map<String, Value>> {
    let mut node = Map::new();
    node.insert("role".into(), json!("entry"));
    node.insert("listeners".into(), gen_listeners(u)?);
    let mut reality = Map::new();
    reality.insert(
        "cover".into(),
        json!(gen_pick(
            u,
            &["www.example.com:443", "93.184.216.34:443", "www.example.com"]
        )?),
    );
    reality.insert("privateKey".into(), json!(gen_key(u)?));
    if u.ratio(1, 3)? {
        reality.insert(
            "serverNames".into(),
            json!([gen_pick(u, &["www.example.com", "*.example.com", "*"])?]),
        );
    }
    if u.ratio(1, 4)? {
        reality.insert("maxTimeDiffMs".into(), json!(gen_u64(u)?));
    }
    node.insert("reality".into(), Value::Object(reality));

    let mut users = Vec::new();
    for _ in 0..u.int_in_range(0..=2_usize)? {
        users.push(gen_user(u)?);
    }
    node.insert("users".into(), Value::Array(users));

    if u.ratio(1, 2)? {
        let mut outbounds = Map::new();
        for _ in 0..u.int_in_range(0..=2_usize)? {
            outbounds.insert(gen_outbound_name(u)?, gen_outbound(u)?);
        }
        node.insert("outbounds".into(), Value::Object(outbounds));
    }
    node.insert("routing".into(), gen_routing(u)?);
    if u.ratio(1, 4)? {
        node.insert(
            "assets".into(),
            json!({ "geoip": gen_pick(u, &["https://a.example/geoip.dat", "http://a/x"])? }),
        );
    }
    Ok(node)
}

fn gen_landing(u: &mut Unstructured<'_>) -> Result<Map<String, Value>> {
    let mut node = Map::new();
    node.insert("role".into(), json!("landing"));
    node.insert("listeners".into(), gen_listeners(u)?);

    let mut landing = Map::new();
    let protocol = gen_pick(u, &["handoff", "nxr"])?;
    landing.insert("protocol".into(), json!(protocol.clone()));
    landing.insert("psk".into(), json!(gen_key(u)?));
    if protocol == "handoff" {
        landing.insert("privateKey".into(), json!(gen_key(u)?));
        if u.ratio(1, 3)? {
            landing.insert("previousPsks".into(), json!([gen_key(u)?, gen_key(u)?]));
        }
    }
    if u.ratio(1, 3)? {
        landing.insert("maxTimeDifferenceSeconds".into(), json!(gen_u64(u)?));
        landing.insert("authenticationTimeoutMs".into(), json!(gen_u64(u)?));
    }
    node.insert("landing".into(), Value::Object(landing));

    if u.ratio(1, 3)? {
        node.insert("egress".into(), json!(gen_outbound_name(u)?));
    }
    if u.ratio(1, 3)? {
        node.insert(
            "outbounds".into(),
            json!({ gen_outbound_name(u)?: gen_outbound(u)? }),
        );
    }
    Ok(node)
}

fn gen_structured(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let mut node = match u.int_in_range(0..=3_u8)? {
        0..=1 => gen_entry(u)?,
        2 => gen_landing(u)?,
        _ => {
            // An unknown or missing role must reach the dispatch reject.
            let mut node = Map::new();
            if u.ratio(3, 4)? {
                node.insert("role".into(), json!(gen_text(u, 8)?));
            }
            node.insert("listeners".into(), gen_listeners(u)?);
            node
        }
    };
    if u.ratio(1, 2)? {
        node.insert("log".into(), gen_log(u)?);
    }
    if u.ratio(1, 3)? {
        node.insert("dns".into(), gen_dns(u)?);
    }
    if u.ratio(1, 4)? {
        node.insert("network".into(), json!({ "ip": gen_pick(u, &["auto", "ipv4Only"])? }));
    }
    if u.ratio(1, 4)? {
        node.insert(
            "runtime".into(),
            json!({
                "tuning": gen_pick(u, &["startup", "adaptive", "fixed"])?,
                "limits": { "maxConnections": gen_u64(u)?, "maxHandshakes": gen_u64(u)? },
            }),
        );
    }
    let mut document = serde_json::to_vec(&Value::Object(node)).unwrap_or_default();

    // One byte-level tail mutation keeps lexer-level rejects reachable.
    match u.int_in_range(0..=4_u8)? {
        0 => {}
        1 => {
            let keep = u.int_in_range(0..=document.len())?;
            document.truncate(keep);
        }
        2 => {
            let extra: Vec<u8> = u.arbitrary()?;
            document.extend(extra.iter().take(64));
        }
        3 => {
            document.push(b'{');
        }
        _ => {
            let key = gen_text(u, 8)?;
            document.extend(format!(",\"{key}\":null}}").into_bytes());
        }
    }
    Ok(document)
}

fuzz_target!(|input: &[u8]| {
    let mut unstructured = Unstructured::new(input);
    let bytes = match unstructured.ratio(15, 16) {
        Ok(true) => match gen_structured(&mut unstructured) {
            Ok(document) => document,
            Err(_) => return,
        },
        _ => input.to_vec(),
    };
    let _ = fuzz_load(&bytes);
});
