//! Inventory-anchored listener policy and the separately labelled Handoff entry.

use super::{Candidate, Host, HostSnapshot, Plan, Transport, Value, checked, string};
use crate::{
    deploy::{host::HostRole, remote::validate_remote_argv, snapshot},
    perf::json_out::Json,
};
use std::path::{Path, PathBuf};

/// An already staged temporary LINE service; the runner never creates or rewrites it.
#[derive(Debug, Clone)]
pub struct Supplemental {
    /// Dedicated `rust-reality-canary-*.service` on the canonical LINE alias.
    pub service: String,
    /// Its sole listener, on IPv4 loopback.
    pub port: u16,
    /// Second loopback SOCKS inbound in the same stock-Xray configuration.
    pub public_socks_port: u16,
    /// Download through the unchanged public LINE route.
    pub public_url: String,
    /// Exact independently retained reference bytes for that download.
    pub public_payload: PathBuf,
}

impl Supplemental {
    pub(super) fn host(&self, line: &Host) -> Result<Host, String> {
        Host::new(HostRole::Line, line.alias(), &self.service)
    }

    fn validate(&self, socks_port: u16) -> Result<(), String> {
        let name = self
            .service
            .strip_prefix("rust-reality-canary-")
            .and_then(|name| name.strip_suffix(".service"));
        if !name.is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return Err("supplemental unit must be rust-reality-canary-<name>.service".to_owned());
        }
        if self.port < 1024 || self.public_socks_port < 1024 || self.public_socks_port == socks_port
        {
            return Err(
                "supplemental and public SOCKS ports must be unprivileged; SOCKS ports must differ"
                    .to_owned(),
            );
        }
        if !self.public_payload.is_file()
            || self
                .public_payload
                .metadata()
                .map_err(|error| error.to_string())?
                .len()
                == 0
        {
            return Err("public-path reference payload must be a nonempty file".to_owned());
        }
        if !(self.public_url.starts_with("http://") || self.public_url.starts_with("https://")) {
            return Err("public-path URL must use http:// or https://".to_owned());
        }
        Ok(())
    }
}

pub(super) fn validate(plan: &Plan) -> Result<(), String> {
    baseline(&plan.line_baseline, "rust-reality-vps")?;
    baseline(&plan.landing_baseline, "rust-reality-landing-vps")?;
    if let Some(supplemental) = &plan.supplemental {
        supplemental.validate(plan.socks_port)?;
    }
    if !plan.origin_access_log.starts_with('/') {
        return Err("origin access log must be an absolute remote path".to_owned());
    }
    validate_remote_argv(&["cat".to_owned(), plan.origin_access_log.clone()])?;
    if plan.upload_url.contains(['?', '#']) {
        return Err("upload endpoint must be a URL path without query or fragment".to_owned());
    }
    for (path, minimum, exact) in [
        (&plan.payload_one_mib, 1_048_576, true),
        (&plan.payload_large, 1_048_577, false),
    ] {
        let size = path
            .metadata()
            .map_err(|error| format!("payload metadata: {error}"))?
            .len();
        if (exact && size != minimum) || (!exact && size < minimum) {
            return Err(
                "payloads must be exactly one MiB and strictly larger than one MiB".to_owned(),
            );
        }
    }
    Ok(())
}

pub(super) fn validate_inbounds(inbounds: &[Value], plan: &Plan) -> Result<(), String> {
    if inbounds
        .iter()
        .any(|inbound| inbound.optional("listen").and_then(string) != Some("127.0.0.1"))
    {
        return Err("every canary Xray inbound must explicitly bind 127.0.0.1".to_owned());
    }
    for port in std::iter::once(plan.socks_port).chain(
        plan.supplemental
            .iter()
            .map(|value| value.public_socks_port),
    ) {
        let count = inbounds
            .iter()
            .filter(|inbound| {
                inbound.optional("protocol").and_then(string) == Some("socks")
                    && inbound
                        .optional("port")
                        .and_then(|value| value.as_int("port").ok())
                        == Some(i64::from(port))
            })
            .count();
        if count != 1 {
            return Err(format!(
                "Xray config requires exactly one 127.0.0.1:{port} SOCKS inbound"
            ));
        }
    }
    Ok(())
}

fn baseline(path: &Path, alias: &str) -> Result<HostSnapshot, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("baseline {}: {error}", path.display()))?;
    let snapshot = snapshot::from_json(&text)?;
    if snapshot.alias != alias || !snapshot.service_healthy() || !snapshot.ssh_22_present {
        return Err(format!(
            "baseline must record healthy {alias} before cutover"
        ));
    }
    Ok(snapshot)
}

pub(super) fn listeners_unchanged(path: &Path, observed: &HostSnapshot) -> Result<(), String> {
    let before = baseline(path, &observed.alias)?;
    if has_new_wildcard_listener(&before.listeners, &observed.listeners) {
        return Err(format!(
            "{} introduced a wildcard listener relative to the pre-cutover inventory",
            observed.alias
        ));
    }
    Ok(())
}

fn has_new_wildcard_listener(
    before: &[snapshot::Listener],
    observed: &[snapshot::Listener],
) -> bool {
    observed
        .iter()
        .any(|listener| listener.is_wildcard() && !before.contains(listener))
}

pub(super) fn verify_supplemental(
    transport: &mut impl Transport,
    host: &Host,
    candidate: &Candidate,
    port: u16,
) -> Result<HostSnapshot, String> {
    let state = snapshot::inspect(transport, host)?;
    super::verify_candidate(&state, candidate)?;
    let listeners = checked(
        transport,
        host,
        true,
        &["ss".to_owned(), "-ltnpH".to_owned()],
        "inspect supplemental listener ownership",
    )?;
    if !loopback_listener_owned(&listeners, state.pid, port) {
        return Err(
            "supplemental process must own exactly its declared loopback listener".to_owned(),
        );
    }
    Ok(state)
}

fn loopback_listener_owned(listeners: &str, pid: Option<u32>, port: u16) -> bool {
    let Some(pid) = pid else {
        return false;
    };
    let owner = format!("pid={pid},");
    let rows: Vec<_> = listeners
        .lines()
        .filter(|line| line.contains(&owner))
        .collect();
    rows.len() == 1
        && snapshot::parse_ss_listener(rows[0])
            .is_some_and(|listener| listener.address == "127.0.0.1" && listener.port == port)
}

pub(super) fn public_probe(plan: &Plan) -> Result<(), String> {
    if let Some(supplemental) = &plan.supplemental {
        let mut public = plan.clone();
        public.socks_port = supplemental.public_socks_port;
        let output = plan.out_dir.join("public-path-download.bin");
        super::curl_request(&public, &supplemental.public_url, Some(&output), None, 60)?;
        super::compare_files(&output, &supplemental.public_payload)?;
    }
    Ok(())
}

pub(super) fn plan_json(plan: &Plan) -> Json {
    let supplemental = plan.supplemental.as_ref().map_or(Json::Null, |value| {
        Json::object([
            ("service", Json::string(value.service.clone())),
            ("port", Json::Int(i64::from(value.port))),
            (
                "publicSocksPort",
                Json::Int(i64::from(value.public_socks_port)),
            ),
            ("publicUrl", Json::string(value.public_url.clone())),
            (
                "publicPayload",
                Json::string(value.public_payload.display().to_string()),
            ),
        ])
    });
    Json::object([
        (
            "lineBaseline",
            Json::string(plan.line_baseline.display().to_string()),
        ),
        (
            "landingBaseline",
            Json::string(plan.landing_baseline.display().to_string()),
        ),
        ("supplemental", supplemental),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_preserves_existing_rpc_but_rejects_new_port_or_address_family() {
        let baseline = snapshot::parse_ss_listener("0.0.0.0:111").unwrap();
        let public = snapshot::parse_ss_listener("0.0.0.0:18443").unwrap();
        let ipv6 = snapshot::parse_ss_listener("[::]:111").unwrap();
        let loopback = snapshot::parse_ss_listener("127.0.0.1:18443").unwrap();
        assert!(!has_new_wildcard_listener(
            std::slice::from_ref(&baseline),
            &[baseline.clone(), loopback]
        ));
        assert!(has_new_wildcard_listener(
            std::slice::from_ref(&baseline),
            &[baseline.clone(), public]
        ));
        assert!(has_new_wildcard_listener(
            std::slice::from_ref(&baseline),
            &[baseline.clone(), ipv6]
        ));
    }

    #[test]
    fn supplemental_listener_requires_exact_owner_loopback_and_port() {
        let row = "LISTEN 0 128 127.0.0.1:18443 0.0.0.0:* users:((\"rust-reality\",pid=42,fd=9))";
        assert!(loopback_listener_owned(row, Some(42), 18443));
        assert!(!loopback_listener_owned(row, Some(4), 18443));
        assert!(!loopback_listener_owned(row, Some(42), 18444));
        assert!(!loopback_listener_owned(
            &row.replace("127.0.0.1", "0.0.0.0"),
            Some(42),
            18443
        ));
        assert!(!loopback_listener_owned(
            &format!("{row}\n{row}"),
            Some(42),
            18443
        ));
        assert!(!loopback_listener_owned("", Some(42), 18443));
    }
}
