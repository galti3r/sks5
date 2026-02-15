# sks5 Testing Guide

## Overview

sks5 has a comprehensive test suite covering unit tests, integration tests, end-to-end tests, property-based tests, browser E2E tests, and performance benchmarks. The project targets **90% code coverage minimum**.

| Category | Count | Location |
|----------|------:|----------|
| Unit tests (lib) | 93 | `src/` (inline `#[cfg(test)]` modules) |
| Unit tests (standalone) | 272 | `tests/unit/` |
| E2E tests | 110+ | `tests/e2e/` |
| Browser E2E tests | 9 | `tests/e2e/browser_dashboard_test.rs` |
| Performance tests | 5 | `tests/e2e/performance_test.rs` |
| Property-based tests | 3 suites | `tests/unit/*_proptest.rs` |
| Benchmarks | 4 suites | `benches/` |
| **Total** | **~738** | |

---

## Quick Reference

```bash
# Run all tests (unit + E2E, excludes #[ignore])
cargo test --all-targets

# Full validation (tests + browser E2E)
cargo test && cargo test --test e2e_browser_dashboard -- --ignored

# Full validation (tests + security scan)
make test-all
```

---

## Running Tests

### Unit Tests

Unit tests cover isolated functions with mocked dependencies: config parsing, ACL matching, authentication, shell commands, SOCKS5 protocol, proxy engine, security, and session management.

```bash
# All unit tests (inline + standalone)
cargo test --all-targets

# Inline lib tests only
make test-unit
# or
cargo test --lib

# Single test file
cargo test --test unit_acl
cargo test --test unit_config
cargo test --test unit_quota

# Single test function
cargo test --test unit_acl -- test_acl_cidr_match
```

**Standalone unit test files** in `tests/unit/`:

| File | Subject |
|------|---------|
| `config_test.rs` | TOML config parsing and defaults |
| `config_validation_test.rs` | Config validation rules |
| `acl_test.rs` | ACL rule parsing and matching |
| `password_test.rs` | Argon2id password hashing |
| `shell_parser_test.rs` | Shell command parser |
| `shell_commands_test.rs` | Shell command execution |
| `socks_protocol_test.rs` | SOCKS5 protocol parsing |
| `socks_protocol_async_test.rs` | Async SOCKS5 protocol handling |
| `socks_auth_test.rs` | SOCKS5 authentication |
| `socks_reply_codes_test.rs` | SOCKS5 RFC 1928 reply codes |
| `socks_protocol_fuzz_test.rs` | Protocol fuzzing with random inputs |
| `socks5_tls_config_test.rs` | TLS SOCKS5 configuration |
| `proxy_engine_test.rs` | Proxy engine ACL + connect |
| `proxy_engine_unit_test.rs` | Proxy engine internals |
| `proxy_connection_details_test.rs` | Connection detail tracking |
| `security_test.rs` | Security manager, bans, IP filtering |
| `auth_service_test.rs` | Auth service orchestration |
| `ssh_keys_test.rs` | SSH key generation and encoding |
| `ssh_handler_test.rs` | SSH handler logic |
| `pubkey_test.rs` | Public key authentication |
| `certificate_auth_test.rs` | SSH certificate authentication |
| `audit_test.rs` | Audit event creation |
| `audit_dropped_test.rs` | Audit channel overflow handling |
| `audit_logger_test.rs` | Audit file logger |
| `audit_improvements_test.rs` | Audit enrichment |
| `forwarder_test.rs` | TCP forwarder |
| `forwarder_unit_test.rs` | Forwarder internals |
| `connector_test.rs` | Outbound TCP connector |
| `connector_unit_test.rs` | Connector internals |
| `dns_cache_test.rs` | DNS cache TTL logic |
| `geoip_test.rs` | GeoIP integration |
| `geoip_unit_test.rs` | GeoIP unit logic |
| `webhook_test.rs` | Webhook delivery |
| `cli_test.rs` | CLI argument parsing |
| `context_test.rs` | Request context |
| `socks_handler_test.rs` | SOCKS5 handler |
| `pre_auth_check_test.rs` | Pre-authentication IP checks |
| `user_source_ip_test.rs` | Per-user source IP validation |
| `sse_ticket_test.rs` | HMAC SSE ticket generation |
| `ip_rate_limiter_test.rs` | Per-IP rate limiting |
| `metrics_cardinality_test.rs` | Metrics label cardinality cap |
| `metrics_unit_test.rs` | Prometheus metrics internals |
| `new_features_test.rs` | Connection pool, retry, MOTD, time access, groups, roles |
| `quota_test.rs` | Quota tracker, rolling windows, daily/monthly quotas |
| `pool_test.rs` | TCP connection pool |
| `ip_guard_test.rs` | Anti-SSRF IP guard |
| `ip_reputation_test.rs` | IP reputation scoring |
| `retry_test.rs` | Smart retry with backoff |
| `totp_extraction_test.rs` | TOTP code extraction from password |
| `alerting_test.rs` | Alert rule evaluation |
| `rate_limit_test.rs` | Multi-window rate limiting |
| `api_test.rs` | REST API endpoints |

### Property-Based Tests

Using [proptest](https://crates.io/crates/proptest) for randomized input testing:

```bash
cargo test --test unit_acl_proptest
cargo test --test unit_shell_parser_proptest
cargo test --test unit_config_proptest
```

These tests generate random ACL rules, shell commands, and config values to find edge cases that hand-written tests might miss.

### E2E Tests

E2E tests start a real sks5 server (SSH + SOCKS5 + API) and exercise it through actual SSH/SOCKS5/HTTP clients.

```bash
# All E2E tests (excludes #[ignore])
make test-e2e
# or
cargo test --test '*'

# All E2E tests including ignored (IPv6, performance)
make test-e2e-all
# or
cargo test --test '*' -- --include-ignored

# Specific E2E test file
cargo test --test e2e_auth
cargo test --test e2e_shell
cargo test --test e2e_acl_fqdn
```

**E2E test files** in `tests/e2e/`:

| File | Tests | Subject |
|------|------:|---------|
| `auth_test.rs` | 5 | Password success/failure, unknown user, retry |
| `shell_test.rs` | 16 | Exec commands, dangerous commands blocked, interactive shell |
| `shell_commands_test.rs` | 18 | show status/bandwidth/connections, help, echo, alias |
| `acl_fqdn_test.rs` | - | FQDN ACL rules |
| `acl_subnet_test.rs` | - | Subnet/CIDR ACL rules |
| `acl_combined_test.rs` | - | Combined ACL rules |
| `acl_ipv6_test.rs` | - | IPv6 ACL rules (`#[ignore]` -- needs IPv6) |
| `forwarding_test.rs` | 3 | Local forward, large data, denied user |
| `rejection_test.rs` | 8 | SFTP, reverse forward, bash/sh/nc/rsync blocked |
| `socks5_server_test.rs` | 11 | Auth, forwarding, concurrency, anti-SSRF |
| `socks5_standalone_test.rs` | - | Standalone SOCKS5 listener |
| `socks5_timeout_test.rs` | - | SOCKS5 handshake timeout |
| `api_dashboard_test.rs` | 12 | Health, users, connections, bans, maintenance, dashboard, SSE |
| `api_users_details_test.rs` | - | API user detail endpoints |
| `api_audit_improvements_test.rs` | - | API audit events |
| `api_groups_test.rs` | - | API group management |
| `api_sessions_test.rs` | - | API session management |
| `quota_api_test.rs` | 10 | Quota listing, reset, enforcement, Prometheus metrics |
| `reload_test.rs` | 3 | Config hot-reload (valid/invalid, auth) |
| `status_test.rs` | 3 | Health, Prometheus, maintenance mode |
| `autoban_test.rs` | 3 | Auto-ban trigger, rejection, no false positive |
| `audit_trail_test.rs` | 2 | Auth success/failure audit events |
| `webhook_test.rs` | - | Webhook delivery |
| `webhook_retry_test.rs` | - | Webhook retry with backoff |
| `sse_ticket_e2e_test.rs` | - | HMAC SSE ticket auth |
| `sse_payload_test.rs` | - | SSE event payloads |
| `ws_test.rs` | - | WebSocket events |
| `ssh_session_test.rs` | - | SSH session lifecycle |
| `metrics_server_test.rs` | - | Prometheus metrics endpoint |
| `performance_test.rs` | 5 | Throughput, latency, concurrency |
| `backup_restore_test.rs` | - | Config backup/restore |
| `cli_e2e_test.rs` | - | CLI command E2E |
| `browser_dashboard_test.rs` | 9 | Browser-based dashboard tests |

### Browser E2E Tests

Browser E2E tests verify the web dashboard in a real Chrome browser. They are marked `#[ignore]` and require Podman.

**Prerequisites:**
- Podman installed and available in `$PATH`
- Network access to pull `docker.io/chromedp/headless-shell:latest`
- No other process using the dynamically assigned ports

```bash
# Using make (recommended -- handles cleanup)
make test-e2e-browser

# Using cargo directly
cargo test --test e2e_browser_dashboard -- --ignored --nocapture

# With debug logging
RUST_LOG=debug cargo test --test e2e_browser_dashboard -- --ignored --nocapture
```

**How it works:**
1. Tests auto-start a Chrome Headless container via `podman run --network=host`
2. The container exposes Chrome DevTools Protocol (CDP) on a random port
3. The `chromiumoxide` crate connects to CDP and controls the browser
4. Each test starts an sks5 server with API enabled, opens the dashboard, and validates DOM state
5. The container is shared across all tests in the binary (via `OnceCell`)
6. Cleanup happens automatically; `make test-e2e-browser` also stops leftover containers

**What is tested:**
- Dashboard page loads with correct title and stat cards
- Theme toggle (dark/light) works
- WebSocket connects and shows "Connected" status
- Live data updates arrive via WS/SSE
- User table is populated
- Maintenance mode toggle via dashboard button
- Disconnect shows offline status
- Stat card structure (4 cards with expected headings)
- Controls panel has expected buttons and elements

**Troubleshooting:**
- If tests fail with "podman not available", install Podman (`apt install podman` or equivalent)
- If Chrome fails to start, check `podman ps -a` for leftover containers: `podman rm -f $(podman ps -aq --filter name=sks5-chrome)`
- On CI runners without Podman, the tests skip gracefully (checking `podman_available()`)

### Performance Tests

Performance tests measure throughput, latency, and concurrency. They are `#[ignore]` by default.

```bash
make test-perf
# or
cargo test --test e2e_performance -- --ignored --nocapture
```

**Performance targets:**

| Metric | Target | Test |
|--------|--------|------|
| SSH forward throughput | > 1 MB/s | `test_throughput_ssh_forward` |
| SOCKS5 throughput | > 1 MB/s | `test_throughput_socks5` |
| SSH auth latency (avg of 20) | < 5 seconds | `test_ssh_auth_latency` |
| Concurrent SSH connections | 50 (>= 50% succeed) | `test_concurrent_ssh_connections` |
| Concurrent SOCKS5 connections | 50 (>= 50% succeed) | `test_concurrent_socks5_connections` |

Performance results are printed to stderr with `[PERF]` prefix for easy grepping.

---

## Benchmarks

Criterion benchmarks for hot-path performance:

```bash
# Run all benchmarks
cargo bench
# or
make bench

# Run a specific benchmark suite
cargo bench --bench acl_bench
cargo bench --bench password_bench
cargo bench --bench config_bench
cargo bench --bench socks5_bench
```

**Benchmark suites** in `benches/`:

| File | Subject |
|------|---------|
| `acl_bench.rs` | ACL rule parsing and matching (simple, CIDR, wildcard, 10/100 rules, verbose) |
| `password_bench.rs` | Argon2id password hashing |
| `config_bench.rs` | TOML config parsing |
| `socks5_bench.rs` | SOCKS5 protocol parsing |

HTML benchmark reports are generated in `target/criterion/` when using the default Criterion configuration.

---

## Code Coverage

The project targets **90% code coverage minimum**, enforced in CI.

### Using cargo-tarpaulin (CI default)

```bash
# Install
cargo install cargo-tarpaulin

# Generate coverage with 90% threshold (fails if below)
cargo tarpaulin --all-targets --fail-under 90 --out xml --output-dir coverage/

# Generate HTML report
cargo tarpaulin --all-targets --out html --output-dir coverage/
```

### Using cargo-llvm-cov (local alternative)

```bash
# Install
cargo install cargo-llvm-cov

# Generate coverage
cargo llvm-cov --all-targets

# or via make
make coverage
```

---

## Test Organization

### Directory Structure

```
tests/
  unit/                           # Standalone unit tests
    config_test.rs                # One file per module/concern
    acl_test.rs
    acl_proptest.rs               # Property-based tests
    ...
    test_support.rs               # Shared test utilities
  e2e/                            # End-to-end tests
    helpers.rs                    # Shared E2E helpers (server start, clients, etc.)
    auth_test.rs                  # One file per feature area
    shell_test.rs
    ...
    performance_test.rs           # Performance tests (#[ignore])
    browser_dashboard_test.rs     # Browser E2E tests (#[ignore])
benches/
    acl_bench.rs                  # Criterion benchmarks
    password_bench.rs
    config_bench.rs
    socks5_bench.rs
```

### Conventions

- Each test file is registered as a `[[test]]` entry in `Cargo.toml`
- E2E tests use a shared `helpers.rs` module (`mod helpers; use helpers::*;`)
- Unit tests use a shared `test_support.rs` where needed
- Tests that require external dependencies (Podman, IPv6) are marked `#[ignore]`
- Test TOML configs use `r##"..."##` or `format!()` to avoid Rust 2021 `$identifier` issues

---

## Adding New Tests

### Adding a Unit Test

1. Create a file in `tests/unit/`, e.g. `tests/unit/my_feature_test.rs`
2. Add a `[[test]]` entry to `Cargo.toml`:
   ```toml
   [[test]]
   name = "unit_my_feature"
   path = "tests/unit/my_feature_test.rs"
   ```
3. Write tests using standard `#[test]` or `#[tokio::test]`:
   ```rust
   use sks5::my_module::MyType;

   #[test]
   fn test_my_feature_does_something() {
       let result = MyType::new().do_something();
       assert_eq!(result, expected);
   }
   ```

### Adding an E2E Test

1. Create a file in `tests/e2e/`, e.g. `tests/e2e/my_feature_e2e_test.rs`
2. Add a `[[test]]` entry to `Cargo.toml`:
   ```toml
   [[test]]
   name = "e2e_my_feature"
   path = "tests/e2e/my_feature_e2e_test.rs"
   ```
3. Import the shared helpers:
   ```rust
   #[allow(dead_code, unused_imports)]
   mod helpers;
   use helpers::*;

   #[tokio::test]
   async fn test_my_feature_e2e() {
       let ssh_port = free_port().await;
       let hash = hash_pass("pass");
       let _server = start_ssh(ssh_config(ssh_port, &hash)).await;
       // ... test logic using real SSH/SOCKS5 clients
   }
   ```

### Adding a Benchmark

1. Create a file in `benches/`, e.g. `benches/my_feature_bench.rs`
2. Add a `[[bench]]` entry to `Cargo.toml`:
   ```toml
   [[bench]]
   name = "my_feature_bench"
   harness = false
   ```
3. Write the benchmark using Criterion:
   ```rust
   use criterion::{black_box, criterion_group, criterion_main, Criterion};

   fn bench_my_function(c: &mut Criterion) {
       c.bench_function("my_function", |b| {
           b.iter(|| {
               my_function(black_box(input));
           });
       });
   }

   criterion_group!(benches, bench_my_function);
   criterion_main!(benches);
   ```

---

## CI Integration

Tests are run automatically in CI on every push and pull request. See [CI-CD.md](CI-CD.md) for full pipeline details.

| Stage | Command | Blocking |
|-------|---------|:--------:|
| Lint | `cargo fmt --check` + `cargo clippy -D warnings` | Yes |
| Unit + E2E | `cargo test --all-targets` | Yes |
| Browser E2E | `cargo test --test e2e_browser_dashboard -- --ignored` | No (allow_failure) |
| Coverage | `cargo tarpaulin --fail-under 90` | Yes |
| Security | `cargo audit` + `cargo deny check` | Yes |

---

## Makefile Reference

| Target | Description |
|--------|-------------|
| `make test` | Run all tests (`cargo test --all-targets`) |
| `make test-unit` | Unit tests only (`cargo test --lib`) |
| `make test-e2e` | E2E tests only (`cargo test --test '*'`) |
| `make test-e2e-all` | E2E tests including `#[ignore]` |
| `make test-e2e-browser` | Browser E2E tests (requires Podman) |
| `make test-perf` | Performance tests |
| `make test-e2e-podman` | E2E tests in Podman containers |
| `make test-all` | Full suite: tests + security scan |
| `make bench` | Run all Criterion benchmarks |
| `make coverage` | Generate code coverage report |
| `make security-scan` | `clippy` + `cargo-audit` + `cargo-deny` |
