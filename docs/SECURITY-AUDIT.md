# sks5 Security Audit Report

**Date**: 2026-02-07 (updated 2026-02-09)
**Auditor**: Automated code review
**Scope**: Full codebase review — authentication, ACL/proxy/SSRF, input validation, DoS resilience
**Codebase**: 57 source files, 738+ tests, 0 `unsafe` blocks

---

## Executive Summary

The sks5 codebase demonstrates strong security practices overall. Safe Rust throughout (zero `unsafe`), proper error handling, bounded protocol fields, anti-SSRF IP guard, connection semaphores, rate limiting with capacity caps, and ban management show thoughtful security design. All critical and high findings have been remediated. The remaining open items are low-priority hardening tasks.

| Severity | Count | Fixed | Open |
|----------|-------|-------|------|
| CRITICAL | 5 | 5 | 0 |
| HIGH | 8 | 8 | 0 |
| MEDIUM | 12 | 11 | 1 |
| LOW | 7 | 4 | 3 |
| INFO (positive) | 11 | — | — |

---

## CRITICAL Findings

### C-1: Dashboard Endpoint Bypasses API Auth Middleware — FIXED

**File**: `src/api/mod.rs`

Routes now use `.route_layer()` to apply auth middleware consistently. All authenticated routes are placed inside a properly protected Router block.

---

### C-2: API Bearer Token Non-Constant-Time Comparison — FIXED

**File**: `src/api/mod.rs`

Uses `subtle::ConstantTimeEq` for constant-time token comparison.

---

### C-3: SSE Token in Query Param + Non-Constant-Time Comparison — FIXED

**File**: `src/api/sse.rs`, `src/api/mod.rs`

Implemented HMAC-SHA256 ticket system with 30-second expiry. Fallback token auth uses constant-time comparison.

---

### C-4: Webhook SSRF — No URL Validation on Destinations — FIXED

**File**: `src/webhooks/mod.rs`, `src/config/mod.rs`

Config validation at startup via `validate_webhooks()`. DNS rebinding protection via `check_webhook_dns()` with `ip_guard::is_dangerous_ip()` check. Configurable `allow_private_ips` flag.

---

### C-5: Webhook Client Has No Timeout — FIXED

**File**: `src/webhooks/mod.rs`

`reqwest::Client::builder()` with `connect_timeout(5s)` and `timeout(10s)`.

---

## HIGH Findings

### H-1: Empty API Token Disables All API Auth — FIXED

**File**: `src/config/mod.rs`, `src/api/mod.rs`

Config validation at startup enforces non-empty token when API is enabled. Defense-in-depth check in middleware.

---

### H-2: exec_request / shell_request Lack Explicit Auth Check — FIXED

**File**: `src/ssh/handler.rs`

`shell_request()`, `exec_request()`, and `data()` all check `self.session_state.authenticated` before proceeding.

---

### H-3: Separate Password/Pubkey Attempt Counters — FIXED

**File**: `src/ssh/handler.rs`

Single unified `total_auth_attempts` counter incremented for both password and pubkey auth attempts.

---

### H-4: IPv4-Mapped IPv6 Not Normalized in Ban Manager — FIXED

**File**: `src/security/normalize.rs`, `src/security/mod.rs`

Standalone `normalize_ip()` function converts IPv4-mapped IPv6 (`::ffff:x.x.x.x`) to IPv4. Applied before all ban and security checks.

---

### H-5: IPv4-Mapped IPv6 Not Normalized in IP Filter — FIXED

**File**: `src/security/ip_filter.rs`

Uses `normalize_ip()` before checking against allowed networks.

---

### H-6: TCP Connection Established Before ACL Post-Check (Port Scanning Oracle) — FIXED

**File**: `src/proxy/connector.rs`

`resolve_and_check()` resolves DNS AND applies `ip_guard` filtering before returning addresses. TCP connect only happens to pre-filtered addresses.

---

### H-7: SOCKS5 30s Timeout Wraps Entire Relay — FIXED

**File**: `src/socks/handler.rs`

Handshake timeout applied only to `socks5_handshake()`. Relay phase runs separately under its own idle timeout.

---

### H-8: No Config File Size Limit — FIXED

**File**: `src/config/mod.rs`

`MAX_CONFIG_SIZE` constant (1 MB). File size checked before reading.

---

## MEDIUM Findings

### M-1: User Enumeration via Timing on Password Auth — FIXED

**File**: `src/auth/mod.rs`

Dummy Argon2 verification for non-existent users prevents timing-based user enumeration.

---

### M-2: Config Reload Clears All Bans and Rate Limiters — FIXED

**File**: `src/security/ban.rs`

`update_config()` method preserves existing bans and failure records across reloads.

---

### M-3: No Pre-Auth Ban Check at SSH Connection Level — OPEN

**File**: `src/server.rs`

`new_client()` creates a handler without ban/IP check at the SSH transport level. Banned IPs still perform SSH key exchange. Pre-auth checks exist in `auth_password()`, `auth_publickey()`, and `auth_none()`, limiting the impact.

---

### M-4: Ban Manager Memory Growth Under Distributed Brute-Force — FIXED

**File**: `src/security/ban.rs`

Capacity check: refuses to track new IPs when failure map exceeds 100,000 entries.

---

### M-5: Audit Log Grows Unboundedly — FIXED

**File**: `src/audit/mod.rs`

Size-based log rotation with configurable `max_size_bytes` and `max_files`.

---

### M-6: Audit Channel Flooding — Critical Events Dropped — FIXED

**File**: `src/audit/mod.rs`, `src/audit/events.rs`

Critical events (ACL denials, bans, config reloads, auth failures) get priority delivery via `try_reserve()` fallback when channel is full.

---

### M-7: `100.64.0.0/10` (CGNAT) Not Blocked by ip_guard — FIXED

**File**: `src/proxy/ip_guard.rs`

CGNAT range check added and verified by tests.

---

### M-8: IPv6 6to4 (`2002::/16`) Can Embed Private IPv4 — FIXED

**File**: `src/proxy/ip_guard.rs`

6to4 address detection extracts embedded IPv4 and re-checks against `ip_guard`. Tests verify embedded private addresses are caught.

---

### M-9: Port 0 Not Rejected — FIXED

**File**: `src/proxy/connector.rs`

Port 0 rejected early in the connector.

---

### M-10: Passwords Not Zeroed from Memory — FIXED

**File**: `src/socks/auth.rs`

Uses `zeroize::Zeroizing<String>` for SOCKS5 credential password field.

---

### M-11: GeoIP Lookup Failure Defaults to Allow (Fail-Open) — FIXED

**File**: `src/geoip/mod.rs`, `src/config/types.rs`

Configurable `fail_closed` parameter in `GeoIpConfig`. When enabled, lookup failures result in connection denial.

---

### M-12: Shell exec_request Bypasses Terminal 4096-Byte Limit — FIXED

**File**: `src/ssh/handler.rs`

Data size check (4096 bytes) on exec_request data before executing.

---

## LOW Findings

| ID | File | Description | Status |
|----|------|-------------|--------|
| L-1 | `src/auth/password.rs` | `generate_password` modulo bias (~0.000002%, negligible) | ACCEPTED |
| L-2 | `src/auth/password.rs` | Argon2 at OWASP minimum params (m=19456, t=2, p=1) | ACCEPTED |
| L-3 | `src/ssh/handler.rs` | No `auth_none` handler — now implemented | FIXED |
| L-4 | `src/security/ban.rs` | Ban whitelist doesn't support CIDR ranges | FIXED |
| L-5 | `src/security/ban.rs` | Expired bans not cleaned in periodic task | FIXED |
| L-6 | `src/proxy/ip_guard.rs` | TEST-NET ranges not blocked | FIXED |
| L-7 | `src/config/acl.rs` | `*.example.com` also matches bare `example.com` | ACCEPTED (documented behavior) |

---

## Positive Findings (INFO)

| ID | File | Assessment |
|----|------|------------|
| I-1 | All `src/` | Zero `unsafe` blocks in entire codebase |
| I-2 | `src/auth/mod.rs` | Error messages non-distinguishing (same `Auth::Reject` for all cases) |
| I-3 | `src/socks/handler.rs` | SOCKS5 always requires password auth, no `NO_AUTH` bypass |
| I-4 | `src/ssh/handler.rs` | Reverse forwarding, SFTP, SCP properly denied |
| I-5 | Multiple | Source IP checks at both global and per-user layers |
| I-6 | Multiple | Sensitive data (password_hash, API token, webhook secret) redacted in `Debug` |
| I-7 | `src/security/ban.rs` | DashMap concurrent access patterns are correct |
| I-8 | `src/ssh/keys.rs` | Host key written with `0o600` mode from start (no TOCTOU) |
| I-9 | `src/socks/mod.rs` | Connection semaphore limits concurrent SOCKS5 connections |
| I-10 | `src/security/rate_limit.rs` | Rate limiter has 10,000 user capacity cap |
| I-11 | `src/proxy/connector.rs` | DNS resolution reused as `SocketAddr` — no traditional DNS rebinding TOCTOU |

---

## Remediation Summary

| Priority | IDs | Status |
|----------|-----|--------|
| **P0** | C-1, C-2, C-3, C-4, C-5 | All FIXED |
| **P1** | H-1, H-4, H-5, H-6, H-7, H-8 | All FIXED |
| **P2** | H-2, H-3, M-1 thru M-6 | All FIXED |
| **P3** | M-7 thru M-12, L-3 thru L-6 | All FIXED |
| **Remaining** | M-3 | SSH pre-auth ban check (low impact, mitigated by auth-level checks) |
| **Accepted** | L-1, L-2, L-7 | Negligible risk, documented behavior |

---

## Tools Recommended for Ongoing Auditing

| Tool | Purpose | CI Integration |
|------|---------|----------------|
| `cargo clippy -D warnings` | Static lint | Already in CI |
| `cargo audit` | CVE in dependencies | In CI (`security` job) |
| `cargo deny check` | Licenses + advisories + sources | In CI (`security` job) |
| `cargo-geiger` | Detect `unsafe` in deps | Manual / CI |
| `cargo-tarpaulin` / `llvm-cov` | Code coverage (target 90%) | In CI (`coverage` job) |
| `cargo-fuzz` (libFuzzer) | Fuzz SOCKS5 parser, shell parser, config | Dedicated fuzz targets |
| `trivy` | Container vulnerability scan | In CI (`docker` job) |
| `hadolint` | Containerfile lint | In CI (`lint` job) |

---

*This report is a code review audit, not a penetration test. Findings are based on static analysis of source code.*
