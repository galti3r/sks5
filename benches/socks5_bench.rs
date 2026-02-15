use criterion::{criterion_group, criterion_main, Criterion};
use sks5::socks::protocol::{TargetAddr, UdpHeader};
use std::hint::black_box;

fn bench_read_greeting(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Valid greeting: version=5, 1 method, method=0x02 (password)
    let greeting_bytes: Vec<u8> = vec![0x05, 0x01, 0x02];

    c.bench_function("read_greeting", |b| {
        b.iter(|| {
            let data = greeting_bytes.clone();
            rt.block_on(async {
                let mut cursor = &data[..];
                let _ = sks5::socks::protocol::read_greeting(&mut cursor).await;
            });
        });
    });
}

fn bench_read_greeting_multiple_methods(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Greeting with 3 methods: no-auth, password, GSSAPI
    let greeting_bytes: Vec<u8> = vec![0x05, 0x03, 0x00, 0x01, 0x02];

    c.bench_function("read_greeting_3_methods", |b| {
        b.iter(|| {
            let data = greeting_bytes.clone();
            rt.block_on(async {
                let mut cursor = &data[..];
                let _ = sks5::socks::protocol::read_greeting(&mut cursor).await;
            });
        });
    });
}

fn bench_udp_header_parse_ipv4(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Ipv4([192, 168, 1, 1], 8080),
    };
    let bytes = header.serialize();

    c.bench_function("udp_header_parse_ipv4", |b| {
        b.iter(|| {
            let _ = UdpHeader::parse(black_box(&bytes));
        });
    });
}

fn bench_udp_header_parse_domain(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Domain("example.com".to_string(), 443),
    };
    let bytes = header.serialize();

    c.bench_function("udp_header_parse_domain", |b| {
        b.iter(|| {
            let _ = UdpHeader::parse(black_box(&bytes));
        });
    });
}

fn bench_udp_header_parse_ipv6(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 53),
    };
    let bytes = header.serialize();

    c.bench_function("udp_header_parse_ipv6", |b| {
        b.iter(|| {
            let _ = UdpHeader::parse(black_box(&bytes));
        });
    });
}

fn bench_udp_header_serialize_ipv4(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Ipv4([10, 0, 0, 1], 80),
    };

    c.bench_function("udp_header_serialize_ipv4", |b| {
        b.iter(|| {
            let _ = black_box(&header).serialize();
        });
    });
}

fn bench_udp_header_serialize_domain(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Domain("example.com".to_string(), 443),
    };

    c.bench_function("udp_header_serialize_domain", |b| {
        b.iter(|| {
            let _ = black_box(&header).serialize();
        });
    });
}

fn bench_udp_header_serialize_long_domain(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Domain(
            "very.long.subdomain.chain.deep.inside.example.com".to_string(),
            443,
        ),
    };

    c.bench_function("udp_header_serialize_long_domain", |b| {
        b.iter(|| {
            let _ = black_box(&header).serialize();
        });
    });
}

fn bench_udp_header_roundtrip(c: &mut Criterion) {
    let header = UdpHeader {
        frag: 0,
        target: TargetAddr::Domain("example.com".to_string(), 443),
    };

    c.bench_function("udp_header_roundtrip", |b| {
        b.iter(|| {
            let bytes = header.serialize();
            let _ = UdpHeader::parse(black_box(&bytes));
        });
    });
}

fn bench_target_addr_host_string(c: &mut Criterion) {
    let ipv4 = TargetAddr::Ipv4([192, 168, 1, 1], 80);
    let ipv6 = TargetAddr::Ipv6(
        [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        443,
    );
    let domain = TargetAddr::Domain("example.com".to_string(), 443);

    let mut group = c.benchmark_group("target_addr_host_string");
    group.bench_function("ipv4", |b| {
        b.iter(|| {
            let _ = black_box(&ipv4).host_string();
        });
    });
    group.bench_function("ipv6", |b| {
        b.iter(|| {
            let _ = black_box(&ipv6).host_string();
        });
    });
    group.bench_function("domain", |b| {
        b.iter(|| {
            let _ = black_box(&domain).host_string();
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_read_greeting,
    bench_read_greeting_multiple_methods,
    bench_udp_header_parse_ipv4,
    bench_udp_header_parse_domain,
    bench_udp_header_parse_ipv6,
    bench_udp_header_serialize_ipv4,
    bench_udp_header_serialize_domain,
    bench_udp_header_serialize_long_domain,
    bench_udp_header_roundtrip,
    bench_target_addr_host_string
);
criterion_main!(benches);
