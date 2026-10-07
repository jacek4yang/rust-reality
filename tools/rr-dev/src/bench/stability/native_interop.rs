//! Offline reconstruction of the stock-Xray/no-CCS interoperability receipt.
#![allow(missing_docs)]

use serde::Deserialize;

use super::schema::{Check, Identity};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Binary {
    path: String,
    sha256: String,
    immutable_during_run: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenSsl {
    path: String,
    sha256: String,
    version: String,
    identity: String,
    tls: String,
    middlebox: bool,
    alpn: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ports {
    cover: u16,
    reality: u16,
    socks: u16,
    origin: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Topology {
    address: String,
    ports: Ports,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Certificate {
    authority: String,
    leaf_san: Vec<String>,
    trust_injection: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Assertions {
    server_hello: bool,
    server_change_cipher_spec: bool,
    pub payload_bytes: u64,
    pub payload_sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    schema_version: u64,
    run_id: String,
    completed_at: String,
    rust_reality: Binary,
    xray: Binary,
    openssl: OpenSsl,
    topology: Topology,
    certificate: Certificate,
    pub assertions: Assertions,
    pub trace: String,
    ok: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Environment {
    host_kernel: String,
    xray_sha256: String,
    xray_identity: String,
    openssl_sha256: String,
}

impl Environment {
    pub fn binds_external_images(&self, xray: &str, openssl: &str) -> bool {
        !self.host_kernel.is_empty()
            && !self.xray_identity.is_empty()
            && self.xray_sha256 == xray
            && self.openssl_sha256 == openssl
    }
}

pub fn parse(bytes: &[u8]) -> Result<Receipt, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn parse_environment(bytes: &[u8]) -> Result<Environment, String> {
    serde_json::from_slice(bytes).map_err(|error| error.to_string())
}

pub fn verify(
    receipt: &Receipt,
    environment: &Environment,
    check: &Check,
    identity: &Identity,
    openssl_prefix: &str,
) -> Result<(), String> {
    let ports = &receipt.topology.ports;
    let mut ports = [ports.cover, ports.reality, ports.socks, ports.origin];
    ports.sort_unstable();
    if !receipt.ok
        || receipt.schema_version != 1
        || receipt.run_id.is_empty()
        || receipt.completed_at.is_empty()
        || receipt.rust_reality.sha256 != identity.candidate.sha256
        || !receipt.rust_reality.immutable_during_run
        || !receipt.xray.immutable_during_run
        || receipt.xray.sha256 != environment.xray_sha256
        || receipt.openssl.sha256 != environment.openssl_sha256
        || environment.host_kernel.is_empty()
        || environment.xray_identity.is_empty()
        || !receipt.openssl.version.starts_with(openssl_prefix)
        || receipt.openssl.identity.lines().next() != Some(receipt.openssl.version.as_str())
        || receipt.openssl.tls != "1.3"
        || receipt.openssl.middlebox
        || receipt.openssl.alpn != ["h2", "http/1.1"]
        || receipt.topology.address != "127.0.0.1"
        || ports[0] == 0
        || ports.windows(2).any(|pair| pair[0] == pair[1])
        || receipt.certificate.authority != "ephemeral self-signed CA"
        || receipt.certificate.leaf_san != ["DNS:localhost", "IP:127.0.0.1"]
        || receipt.certificate.trust_injection != "rust-reality child SSL_CERT_FILE only"
        || !receipt.assertions.server_hello
        || receipt.assertions.server_change_cipher_spec
        || receipt.assertions.payload_bytes != 1_048_576
        || !super::evaluate::digest(&receipt.assertions.payload_sha256, 64)
        || receipt.trace != "openssl-trace.log"
        || check.executed_cases != 1
        || check.argv.len() != 15
    {
        return Err("incomplete or substituted native interoperability receipt".to_owned());
    }
    let expected = [
        identity.evaluator.path.as_str(),
        "bench",
        "run",
        "--suite",
        "no-ccs-interop",
        "--rust-bin",
        &receipt.rust_reality.path,
        "--xray-bin",
        &receipt.xray.path,
        "--openssl-bin",
        &receipt.openssl.path,
        "--run-id",
        &receipt.run_id,
        "--out-dir",
        &check.argv[14],
    ];
    if check.argv != expected || check.argv[14].is_empty() {
        return Err("native interoperability command was substituted".to_owned());
    }
    for digest in [&receipt.xray.sha256, &receipt.openssl.sha256] {
        if !super::evaluate::digest(digest, 64)
            || !check
                .observations
                .iter()
                .any(|artifact| artifact.sha256 == *digest)
        {
            return Err("external interoperability executable was not retained".to_owned());
        }
    }
    Ok(())
}
