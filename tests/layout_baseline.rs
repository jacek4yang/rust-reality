//! Linux x86_64 hot-state size guardrails for the release performance contract.

use std::mem::size_of;

use rust_reality::{
    protocol::{
        reality::{ClientHello, ReplayCache, tls13::TlsApplicationIo},
        vless::{VisionDecoder, VisionEncoder},
    },
    runtime::{AdmissionPermit, DirectBarrier, FdBudget, ResourceGovernor},
    server::reality::RealityEstablished,
};
use tokio::net::TcpStream;

#[test]
fn important_hot_structures_stay_within_recorded_bounds() {
    let sizes = [
        ("ClientHello", size_of::<ClientHello>(), 256),
        ("ReplayCache", size_of::<ReplayCache>(), 32),
        (
            "TlsApplicationIoTcp",
            size_of::<TlsApplicationIo<TcpStream>>(),
            1024,
        ),
        ("VisionDecoder", size_of::<VisionDecoder>(), 256),
        ("VisionEncoder", size_of::<VisionEncoder>(), 512),
        ("AdmissionPermit", size_of::<AdmissionPermit>(), 32),
        ("DirectBarrier", size_of::<DirectBarrier>(), 128),
        ("FdBudget", size_of::<FdBudget>(), 32),
        ("ResourceGovernor", size_of::<ResourceGovernor>(), 32),
        ("RealityEstablished", size_of::<RealityEstablished>(), 2048),
    ];

    for (name, actual, upper_bound) in sizes {
        eprintln!("layout-baseline {name}={actual} upper={upper_bound}");
        assert!(
            actual <= upper_bound,
            "{name} grew to {actual} bytes, above its {upper_bound}-byte locality guardrail"
        );
    }
}
