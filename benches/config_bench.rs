use criterion::{criterion_group, criterion_main, Criterion};
use sks5::config;
use std::hint::black_box;

const FAKE_HASH: &str = "argon2id-fakehash-for-testing";

fn bench_parse_minimal_config(c: &mut Criterion) {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"

[[users]]
username = "test"
password_hash = "{}"
"##,
        FAKE_HASH
    );
    c.bench_function("parse_minimal_config", |b| {
        b.iter(|| {
            let _ = config::parse_config(black_box(&toml));
        });
    });
}

fn bench_parse_full_config(c: &mut Criterion) {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"
socks5_listen = "0.0.0.0:1080"
server_id = "SSH-2.0-sks5_bench"
banner = "benchmark"
shutdown_timeout = 30

[shell]
hostname = "bench"
prompt = "$ "

[limits]
max_connections = 1000
max_connections_per_user = 10
connection_timeout = 300
idle_timeout = 0
max_auth_attempts = 3

[security]
ban_enabled = true
ban_threshold = 5
ban_window = 300
ban_duration = 900
ban_whitelist = ["127.0.0.1"]

[logging]
level = "info"
format = "json"

[metrics]
enabled = true
listen = "127.0.0.1:9090"

[api]
enabled = true
listen = "127.0.0.1:9091"
token = "bench-token"

[acl]
default_policy = "deny"
allow = ["*.example.com:443", "10.0.0.0/8:*", "172.16.0.0/12:80-443"]
deny = ["169.254.169.254:*"]

[[users]]
username = "alice"
password_hash = "{hash}"
allow_shell = true

[users.acl]
default_policy = "deny"
allow = ["*.example.com:443"]
deny = ["169.254.169.254:*"]

[[users]]
username = "bob"
password_hash = "{hash}"
allow_shell = false
"##,
        hash = FAKE_HASH,
    );
    c.bench_function("parse_full_config", |b| {
        b.iter(|| {
            let _ = config::parse_config(black_box(&toml));
        });
    });
}

fn bench_parse_config_with_groups(c: &mut Criterion) {
    let toml = format!(
        r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "SSH-2.0-sks5_bench"

[acl]
default_policy = "deny"
allow = ["*.example.com:443"]
deny = ["169.254.169.254:*"]

[[groups]]
name = "admins"

[groups.acl]
default_policy = "allow"
deny = ["169.254.169.254:*"]

[[groups]]
name = "users"

[groups.acl]
default_policy = "deny"
allow = ["*.example.com:443", "*.example.org:443"]

[[users]]
username = "alice"
password_hash = "{hash}"
group = "admins"
role = "admin"

[[users]]
username = "bob"
password_hash = "{hash}"
group = "users"

[[users]]
username = "charlie"
password_hash = "{hash}"
group = "users"

[[users]]
username = "dave"
password_hash = "{hash}"
"##,
        hash = FAKE_HASH,
    );
    c.bench_function("parse_config_with_groups", |b| {
        b.iter(|| {
            let _ = config::parse_config(black_box(&toml));
        });
    });
}

fn bench_parse_config_many_users(c: &mut Criterion) {
    let mut toml = r##"
[server]
ssh_listen = "0.0.0.0:2222"
server_id = "SSH-2.0-sks5_bench"
"##
    .to_string();
    for i in 0..50 {
        toml.push_str(&format!(
            r##"
[[users]]
username = "user{i}"
password_hash = "{hash}"
"##,
            i = i,
            hash = FAKE_HASH,
        ));
    }
    c.bench_function("parse_config_50_users", |b| {
        b.iter(|| {
            let _ = config::parse_config(black_box(&toml));
        });
    });
}

criterion_group!(
    benches,
    bench_parse_minimal_config,
    bench_parse_full_config,
    bench_parse_config_with_groups,
    bench_parse_config_many_users
);
criterion_main!(benches);
