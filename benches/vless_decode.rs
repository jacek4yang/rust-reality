use std::{
    hint::black_box,
    net::{Ipv4Addr, Ipv6Addr},
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rust_reality::protocol::vless::{Command, VERSION, decode_request};

const USER_ID: [u8; 16] = [0x11; 16];

const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_DOMAIN: u8 = 0x02;
const ADDRESS_TYPE_IPV6: u8 = 0x03;

fn benchmark_vless_decode(criterion: &mut Criterion) {
    let cases = [
        ("ipv4", ipv4_request()),
        ("domain", domain_request(b"example.com", &[])),
        ("ipv6", ipv6_request()),
        (
            "maximum_header",
            domain_request(&[b'a'; u8::MAX as usize], &[0xaa; u8::MAX as usize]),
        ),
    ];

    let mut group = criterion.benchmark_group("vless/decode");

    for (name, packet) in &cases {
        group.throughput(Throughput::Bytes(packet.len() as u64));

        group.bench_with_input(
            BenchmarkId::new(*name, packet.len()),
            packet,
            |bencher, packet| {
                bencher.iter(|| {
                    let decoded = decode_request(black_box(packet.as_slice()))
                        .expect("benchmark request must decode");

                    black_box(decoded);
                })
            },
        );
    }

    group.finish();
}

fn request_prefix(addons: &[u8]) -> Vec<u8> {
    let addons_length =
        u8::try_from(addons.len()).expect("benchmark Addons must fit in the wire length");

    let mut packet = Vec::with_capacity(22 + addons.len());

    packet.push(VERSION);
    packet.extend_from_slice(&USER_ID);
    packet.push(addons_length);
    packet.extend_from_slice(addons);
    packet.push(Command::Tcp.as_byte());
    packet.extend_from_slice(&443_u16.to_be_bytes());

    packet
}

fn ipv4_request() -> Vec<u8> {
    let mut packet = request_prefix(&[]);

    packet.push(ADDRESS_TYPE_IPV4);
    packet.extend_from_slice(&Ipv4Addr::new(203, 0, 113, 10).octets());

    packet
}

fn domain_request(domain: &[u8], addons: &[u8]) -> Vec<u8> {
    let domain_length =
        u8::try_from(domain.len()).expect("benchmark domain must fit in the wire length");

    let mut packet = request_prefix(addons);

    packet.push(ADDRESS_TYPE_DOMAIN);
    packet.push(domain_length);
    packet.extend_from_slice(domain);

    packet
}

fn ipv6_request() -> Vec<u8> {
    let mut packet = request_prefix(&[]);

    packet.push(ADDRESS_TYPE_IPV6);
    packet.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());

    packet
}

criterion_group!(benches, benchmark_vless_decode);
criterion_main!(benches);
