//! Shared deployment fixture: origin payloads, cover TLS, and reserved ports.
//!
//! Owns [`SharedFixture`] construction so section runners can share one prepared
//! origin/cover topology. Process lifecycle still rides on
//! [`super::deployment_state::RunState`].

use std::{collections::BTreeSet, io::Write as _, path::Path};

use crate::hash;

use super::deployment_routing::write_routing_assets;
use super::deployment_state::RunState;

#[derive(Debug)]
pub(crate) struct SharedFixture {
    pub(crate) route_origin_port: u16,
    pub(crate) fixed_origin_port: u16,
    pub(crate) cover_port: u16,
    pub(crate) payload_a: std::path::PathBuf,
    pub(crate) payload_b: std::path::PathBuf,
    pub(crate) sha_a: String,
    pub(crate) sha_b: String,
}

pub(crate) fn prepare_shared_fixture(state: &mut RunState<'_>) -> Result<SharedFixture, String> {
    let route_origin_port = state.port()?;
    let fixed_origin_port = state.port()?;
    let cover_port = state.port()?;
    let payload_a = state.workspace.join("payload-a");
    let payload_b = state.workspace.join("payload-b");
    std::fs::create_dir_all(&payload_a)
        .map_err(|error| format!("could not create {}: {error}", payload_a.display()))?;
    std::fs::create_dir_all(&payload_b)
        .map_err(|error| format!("could not create {}: {error}", payload_b.display()))?;
    super::origin_go::write_setup_payload(&payload_a)?;
    super::origin::write_payload(&payload_a.join("payload-0.bin"), 256)?;
    let mut sizes = BTreeSet::from([1_u64, state.plan.program.longflow_mib]);
    sizes.extend(
        state
            .plan
            .program
            .throughput_cells
            .iter()
            .map(|cell| cell.payload_mib),
    );
    for mebibytes in sizes {
        super::origin::write_payload(
            &payload_a.join(format!("payload-{mebibytes}.bin")),
            mebibytes * 1024 * 1024,
        )?;
    }
    write_inverted_payload(&payload_b.join("payload-1.bin"), 1024 * 1024)?;
    write_routing_assets(&payload_a)?;
    let sha_a = hash::sha256_file(&payload_a.join("payload-1.bin"))?;
    let sha_b = hash::sha256_file(&payload_b.join("payload-1.bin"))?;
    let (certificate, key) = super::origin_tls::generate_self_signed(state.workspace.path())?;
    state.spawn_origin("deployment-origin-a", &payload_a, route_origin_port, None)?;
    state.spawn_origin("deployment-origin-b", &payload_b, fixed_origin_port, None)?;
    state.spawn_origin(
        "deployment-cover",
        &payload_a,
        cover_port,
        Some((&certificate, &key)),
    )?;
    Ok(SharedFixture {
        route_origin_port,
        fixed_origin_port,
        cover_port,
        payload_a,
        payload_b,
        sha_a,
        sha_b,
    })
}

fn write_inverted_payload(path: &Path, size: u64) -> Result<(), String> {
    let chunk: Vec<u8> = (0_u8..=255).rev().cycle().take(256 * 4096).collect();
    let mut file = std::fs::File::create(path)
        .map_err(|error| format!("could not create {}: {error}", path.display()))?;
    let mut remaining = size;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(chunk.len() as u64)).unwrap_or(chunk.len());
        file.write_all(&chunk[..take])
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        remaining -= take as u64;
    }
    Ok(())
}
