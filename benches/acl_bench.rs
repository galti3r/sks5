use criterion::{criterion_group, criterion_main, Criterion};
use sks5::config::acl::{AclRule, ParsedAcl};
use sks5::config::types::AclPolicyConfig;
use std::hint::black_box;

fn bench_acl_parse_simple(c: &mut Criterion) {
    c.bench_function("acl_parse_simple", |b| {
        b.iter(|| {
            let _ = AclRule::parse(black_box("example.com:443"));
        });
    });
}

fn bench_acl_parse_cidr(c: &mut Criterion) {
    c.bench_function("acl_parse_cidr", |b| {
        b.iter(|| {
            let _ = AclRule::parse(black_box("10.0.0.0/8:80-443"));
        });
    });
}

fn bench_acl_parse_wildcard(c: &mut Criterion) {
    c.bench_function("acl_parse_wildcard", |b| {
        b.iter(|| {
            let _ = AclRule::parse(black_box("*.example.com:*"));
        });
    });
}

fn bench_acl_check_no_rules(c: &mut Criterion) {
    let acl = ParsedAcl::from_config(AclPolicyConfig::Allow, &[], &[]).unwrap();
    c.bench_function("acl_check_no_rules", |b| {
        b.iter(|| {
            acl.check(black_box("example.com"), black_box(443), black_box(None));
        });
    });
}

fn bench_acl_check_10_rules(c: &mut Criterion) {
    let allow: Vec<String> = (0..5)
        .map(|i| format!("host{}.example.com:443", i))
        .collect();
    let deny: Vec<String> = (0..5).map(|i| format!("bad{}.example.com:*", i)).collect();
    let acl = ParsedAcl::from_config(AclPolicyConfig::Deny, &allow, &deny).unwrap();
    c.bench_function("acl_check_10_rules", |b| {
        b.iter(|| {
            acl.check(
                black_box("host3.example.com"),
                black_box(443),
                black_box(None),
            );
        });
    });
}

fn bench_acl_check_100_rules(c: &mut Criterion) {
    let allow: Vec<String> = (0..50)
        .map(|i| format!("host{}.example.com:443", i))
        .collect();
    let deny: Vec<String> = (0..50).map(|i| format!("bad{}.example.com:*", i)).collect();
    let acl = ParsedAcl::from_config(AclPolicyConfig::Deny, &allow, &deny).unwrap();
    c.bench_function("acl_check_100_rules", |b| {
        b.iter(|| {
            acl.check(
                black_box("host25.example.com"),
                black_box(443),
                black_box(None),
            );
        });
    });
}

fn bench_acl_check_cidr(c: &mut Criterion) {
    let allow = vec!["10.0.0.0/8:*".to_string(), "172.16.0.0/12:443".to_string()];
    let deny = vec!["192.168.0.0/16:*".to_string()];
    let acl = ParsedAcl::from_config(AclPolicyConfig::Deny, &allow, &deny).unwrap();
    let resolved_ip: std::net::IpAddr = "10.0.5.42".parse().unwrap();
    c.bench_function("acl_check_cidr", |b| {
        b.iter(|| {
            acl.check(
                black_box("internal.host"),
                black_box(8080),
                black_box(Some(resolved_ip)),
            );
        });
    });
}

fn bench_acl_check_hostname_only(c: &mut Criterion) {
    let allow = vec!["*.example.com:443".to_string()];
    let deny = vec!["evil.com:*".to_string(), "10.0.0.0/8:*".to_string()];
    let acl = ParsedAcl::from_config(AclPolicyConfig::Deny, &allow, &deny).unwrap();
    c.bench_function("acl_check_hostname_only", |b| {
        b.iter(|| {
            acl.check_hostname_only(black_box("foo.example.com"), black_box(443));
        });
    });
}

fn bench_acl_check_verbose(c: &mut Criterion) {
    let allow: Vec<String> = (0..20)
        .map(|i| format!("host{}.example.com:443", i))
        .collect();
    let deny: Vec<String> = (0..20).map(|i| format!("bad{}.example.com:*", i)).collect();
    let acl = ParsedAcl::from_config(AclPolicyConfig::Deny, &allow, &deny).unwrap();
    c.bench_function("acl_check_verbose", |b| {
        b.iter(|| {
            acl.check_verbose(
                black_box("host10.example.com"),
                black_box(443),
                black_box(None),
            );
        });
    });
}

criterion_group!(
    benches,
    bench_acl_parse_simple,
    bench_acl_parse_cidr,
    bench_acl_parse_wildcard,
    bench_acl_check_no_rules,
    bench_acl_check_10_rules,
    bench_acl_check_100_rules,
    bench_acl_check_cidr,
    bench_acl_check_hostname_only,
    bench_acl_check_verbose
);
criterion_main!(benches);
