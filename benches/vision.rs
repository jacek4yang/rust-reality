use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::{
    config::{DnsStrategy, GlobalRule, Network, PortMatcher, RoutingConfig, UserPolicy},
    protocol::vless::{Address, Destination, UserId, VisionCommand, VisionDecoder, VisionEncoder},
    server::routing::{EmptyAssetMatcher, RouteContext, RoutingTable},
};

const USER: UserId = UserId::new([0x11; 16]);
const USER_UUID: &str = "11111111-1111-1111-1111-111111111111";

fn vision_benchmarks(criterion: &mut Criterion) {
    decode_benchmarks(criterion);
    raw_decode_benchmarks(criterion);
    encode_benchmarks(criterion);
    routing_benchmarks(criterion);
}

fn decode_benchmarks(criterion: &mut Criterion) {
    let payload = vec![0x5a; 8_000];
    let wire = unpadded_frame(&payload, VisionCommand::Direct);
    let mut group = criterion.benchmark_group("vision/decode");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("8k_single_fragment", |bencher| {
        let mut output = Vec::with_capacity(payload.len());
        bencher.iter(|| {
            let mut decoder = VisionDecoder::new(USER);
            let mode = decoder
                .decode(std::hint::black_box(&wire), &mut output)
                .expect("benchmark frame must decode");
            std::hint::black_box((mode, output.as_slice()));
        });
    });
    group.bench_function("8k_fragmented_64b", |bencher| {
        let mut output = Vec::with_capacity(64);
        bencher.iter(|| {
            let mut decoder = VisionDecoder::new(USER);
            let mut decoded = 0_usize;
            for fragment in wire.chunks(64) {
                let _ = decoder
                    .decode(std::hint::black_box(fragment), &mut output)
                    .expect("fragmented benchmark frame must decode");
                decoded = decoded.saturating_add(output.len());
            }
            std::hint::black_box(decoded);
        });
    });
    group.finish();
}

fn encode_benchmarks(criterion: &mut Criterion) {
    let payload = vec![0x5a; 8_000];
    let mut group = criterion.benchmark_group("vision/encode");
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("8k_csprng_padding", |bencher| {
        let mut output = Vec::with_capacity(8 * 1024);
        bencher.iter(|| {
            let mut encoder = VisionEncoder::with_padding_seed(USER, &[0x5a; 44]);
            encoder
                .encode(
                    std::hint::black_box(&payload),
                    VisionCommand::Direct,
                    false,
                    &mut output,
                )
                .expect("benchmark frame must encode");
            std::hint::black_box(output.as_slice());
        });
    });
    group.finish();
}

/// Measures the raw-mode relay decode: staged copy versus borrowed output.
fn raw_decode_benchmarks(criterion: &mut Criterion) {
    let record = vec![0x5a; 16_384];
    let mut group = criterion.benchmark_group("vision/raw_decode");
    group.throughput(Throughput::Bytes(record.len() as u64));
    group.bench_function("16k_staged", |bencher| {
        let mut decoder = raw_decoder();
        let mut output = Vec::with_capacity(record.len());
        bencher.iter(|| {
            let mode = decoder
                .decode(std::hint::black_box(&record), &mut output)
                .expect("raw benchmark record must decode");
            std::hint::black_box((mode, output.as_slice()));
        });
    });
    group.bench_function("16k_borrowed", |bencher| {
        let mut decoder = raw_decoder();
        let mut output = Vec::new();
        bencher.iter(|| {
            let (mode, payload) = decoder
                .decode_borrowed(std::hint::black_box(&record), &mut output)
                .expect("raw benchmark record must decode");
            std::hint::black_box((mode, payload));
        });
    });
    group.finish();
}

fn raw_decoder() -> VisionDecoder {
    let mut decoder = VisionDecoder::new(USER);
    let end_frame = unpadded_frame(b"x", VisionCommand::End);
    let mut output = Vec::new();
    decoder
        .decode(&end_frame, &mut output)
        .expect("benchmark end frame must decode");
    decoder
}

fn routing_benchmarks(criterion: &mut Criterion) {
    let table = routing_table();
    let destination = Destination::new(Address::Domain("api.example.com".to_owned()), 443);
    let context = RouteContext {
        user_id: USER,
        inbound_tag: "public-reality",
        destination: &destination,
        resolved_ips: &[],
    };
    criterion.bench_function("routing/user_first_match", |bencher| {
        bencher.iter(|| {
            let decision = table
                .select(std::hint::black_box(&context))
                .expect("benchmark route must select");
            std::hint::black_box(decision);
        });
    });
}

fn unpadded_frame(payload: &[u8], command: VisionCommand) -> Vec<u8> {
    let mut wire = USER.as_bytes().to_vec();
    wire.push(command as u8);
    wire.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("benchmark payload length must fit")
            .to_be_bytes(),
    );
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(payload);
    wire
}

fn routing_table() -> RoutingTable {
    let private_rule = GlobalRule {
        name: "private".to_owned(),
        outbound: "blocked".to_owned(),
        domain: Vec::new(),
        ip: vec!["10.0.0.0/8".to_owned()],
        port: Vec::new(),
        network: Vec::new(),
        inbound_tag: Vec::new(),
    };
    let domain_rule = GlobalRule {
        name: "api".to_owned(),
        outbound: "direct".to_owned(),
        domain: vec!["domain:example.com".to_owned()],
        ip: Vec::new(),
        port: vec![PortMatcher("443".to_owned())],
        network: vec![Network::Tcp],
        inbound_tag: vec!["public-reality".to_owned()],
    };
    RoutingTable::compile(
        &RoutingConfig {
            domain_strategy: DnsStrategy::AsIs,
            global_rules: vec![private_rule],
            users: vec![UserPolicy {
                name: "primary".to_owned(),
                user_ids: vec![USER_UUID.to_owned()],
                default_outbound: "direct".to_owned(),
                rules: vec![domain_rule],
            }],
        },
        Arc::new(EmptyAssetMatcher),
        rust_reality::runtime::ResourceGovernor::new(
            &rust_reality::config::ResourceGovernorConfig::default(),
        ),
    )
    .expect("benchmark routing must compile")
}

criterion_group!(benches, vision_benchmarks);
criterion_main!(benches);
