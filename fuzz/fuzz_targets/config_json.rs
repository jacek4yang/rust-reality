#![no_main]

use arbitrary::{Result, Unstructured};
use libfuzzer_sys::fuzz_target;
use rust_reality::config::fuzz_decode_config;
use serde_json::{Map, Value, json};

// Structured config-deserialization target. A small custom generator builds
// JSON shaped like the real configuration grammar — every value is synthetic,
// never a real key, UUID, or capture — then a byte-level tail mutation keeps
// lexer-level rejects reachable. One input in sixteen bypasses the generator
// entirely and fuzzes raw bytes.

const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789.-_:/";

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
        // Short garbage string to reach enum and validation rejects.
        gen_text(u, 8)
    }
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
    Ok(*u.choose(&[0_u16, 1, 80, 443, 1080, 8080, 65_535])?)
}

fn gen_tag(u: &mut Unstructured<'_>) -> Result<String> {
    if u.ratio(3, 4)? {
        Ok((*u.choose(&["public-reality", "direct", "block", "landing", "nxr-out"])?).to_owned())
    } else {
        gen_text(u, 12)
    }
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
                &[
                    "system",
                    "8.8.8.8",
                    "1.1.1.1:53",
                    "https://dns.example/dns-query"
                ],
            )?));
        }
        dns.insert("servers".into(), Value::Array(servers));
    }
    if u.ratio(1, 3)? {
        dns.insert("timeoutMs".into(), json!(gen_u64(u)?));
    }
    Ok(Value::Object(dns))
}

fn gen_client(u: &mut Unstructured<'_>) -> Result<Value> {
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
        let length = *u.choose(&[0_usize, 2, 8, 16, 17])?;
        short_ids.push(json!(gen_hex(u, length)?));
    }
    Ok(json!({
        "id": if u.ratio(4, 5)? { synthetic_uuid } else { gen_text(u, 16)? },
        "shortIds": short_ids,
        "email": gen_text(u, 10)?,
        "flow": gen_pick(u, &["xtls-rprx-vision"])?,
    }))
}

fn gen_vless_inbound(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut clients = Vec::new();
    for _ in 0..u.int_in_range(0..=2_usize)? {
        clients.push(gen_client(u)?);
    }
    // Synthetic 32-byte X25519-shaped base64url; never a real key.
    let mut synthetic_key = String::with_capacity(43);
    for _ in 0..43 {
        synthetic_key.push(char::from(*u.choose(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        )?));
    }
    Ok(json!({
        "protocol": "vless",
        "tag": gen_tag(u)?,
        "listen": { "mode": gen_pick(u, &["auto", "dualStack", "ipv4Only", "ipv6Only"])? },
        "port": gen_port(u)?,
        "settings": {
            "clients": clients,
            "decryption": gen_pick(u, &["none"])?,
        },
        "streamSettings": {
            "network": gen_pick(u, &["tcp"])?,
            "security": gen_pick(u, &["reality", "none"])?,
            "realitySettings": {
                "target": format!("{}:{}", gen_text(u, 10)?, gen_port(u)?),
                "serverNames": [gen_text(u, 10)?],
                "privateKey": synthetic_key,
            },
        },
    }))
}

fn gen_inbound(u: &mut Unstructured<'_>) -> Result<Value> {
    match u.int_in_range(0..=3_u8)? {
        0..=2 => gen_vless_inbound(u),
        _ => Ok(json!({
            "protocol": gen_pick(u, &["nxr", "handoff", "vless", "trojan"])?,
            "tag": gen_tag(u)?,
            "port": gen_port(u)?,
        })),
    }
}

fn gen_outbound(u: &mut Unstructured<'_>) -> Result<Value> {
    // direct/blackhole carry no required settings; the heavier protocols
    // appear rarely so their settings rejects stay reachable without
    // dominating the input space.
    let protocol = gen_pick(
        u,
        &[
            "direct",
            "direct",
            "blackhole",
            "blackhole",
            "socks5",
            "nxr",
            "handoff",
        ],
    )?;
    let mut outbound = Map::new();
    outbound.insert("protocol".into(), json!(protocol));
    outbound.insert("tag".into(), json!(gen_tag(u)?));
    if u.ratio(1, 3)? {
        outbound.insert("settings".into(), json!({}));
    }
    Ok(Value::Object(outbound))
}

fn gen_routing(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut rules = Vec::new();
    for _ in 0..u.int_in_range(0..=3_usize)? {
        rules.push(json!({
            "name": gen_text(u, 8)?,
            "outbound": gen_tag(u)?,
            "ip": [gen_pick(u, &["geoip:private", "geoip:cn"])?],
            "domain": [gen_pick(u, &["geosite:category-ads-all", "full:example.com"])?],
            "port": gen_pick(u, &["443", "1-1024", "53,80"])?,
            "network": gen_pick(u, &["tcp", "udp", "tcp,udp"])?,
        }));
    }
    Ok(json!({
        "domainStrategy": gen_pick(u, &["AsIs", "IPIfNonMatch", "IPOnDemand"])?,
        "globalRules": rules,
        "users": [],
    }))
}

fn gen_structured(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let mut config = Map::new();
    if u.ratio(3, 4)? {
        config.insert("log".into(), gen_log(u)?);
    }
    if u.ratio(1, 3)? {
        config.insert("dns".into(), gen_dns(u)?);
    }
    let mut inbounds = Vec::new();
    for _ in 0..u.int_in_range(0..=3_usize)? {
        inbounds.push(gen_inbound(u)?);
    }
    config.insert("inbounds".into(), Value::Array(inbounds));
    let mut outbounds = Vec::new();
    for _ in 0..u.int_in_range(0..=3_usize)? {
        outbounds.push(gen_outbound(u)?);
    }
    config.insert("outbounds".into(), Value::Array(outbounds));
    if u.ratio(3, 4)? {
        config.insert("routing".into(), gen_routing(u)?);
    }
    if u.ratio(1, 4)? {
        config.insert(
            "advanced".into(),
            json!({ "limits": { "resourceGovernor": { "maxConnections": gen_u64(u)? } } }),
        );
    }
    let mut document = serde_json::to_vec(&Value::Object(config)).unwrap_or_default();

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
    let _ = fuzz_decode_config(&bytes);
});
