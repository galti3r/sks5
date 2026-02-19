# sks5 Architecture

## Overview

sks5 is a lightweight SSH server in Rust that serves as a SOCKS5 proxy with an emulated shell. It supports three modes of forwarding:
- **Dynamic forwarding** (`ssh -D`): SOCKS5 proxy via direct-tcpip channels
- **Local port forwarding** (`ssh -L`): TCP forwarding via direct-tcpip channels
- **Standalone SOCKS5**: Dedicated listener on a separate port (TCP + UDP relay)

## Module Architecture

```
              +----------+
              | main.rs  |  CLI (clap) + bootstrap
              |  cli.rs  |  demo.rs (demo mode)
              +----+-----+
                   |
              +----v------+
              | server.rs  |  Orchestrator (SSH + SOCKS5 + API, SIGHUP)
              | context.rs |  Shared AppContext (Arc)
              +----+-------+
                   |
      +-------+---+----+--------+-----------+
      |        |        |        |           |
 +----v----+  +v-----+ +v-----+ +v--------+ +v-----------+
 |  ssh/   |  |socks/| |config| |  api/   | |persistence/|
 | handler |  |server| |types | |dashboard| |  state     |
 +----+----+  |udp_  | |env   | | sse     | |  userdata  |
      |       |relay  | +--+---+ | reload  | +------------+
 +----v----+  +--+---+    |     +----+----+
 | shell/  |     |   +----v--+       |
 |emulator |     |   | auth/ |       |
 | motd.rs |     |   | store |       |
 +---------+     |   +---+---+       |
                 |       |           |
          +------v-------v-----------v--+
          |         proxy/              |  Shared layer
          | forwarder + acl + connector |  SSH, SOCKS5, API converge
          +-------------------------------+

          +-------------------------------+
          |       security/               |  Pre-auth checks, bans,
          | ban + ip_filter + pre_auth    |  rate limiting, IP reputation
          +-------------------------------+

          +-------------------------------+
          |   quota/ + geoip/ + alerting/ |  Enforcement layers
          | BW/conn quotas, country ACL,  |  alert rules + webhook trigger
          +-------------------------------+

          +-------------------------------+
          | audit/ + metrics/ + webhooks/ |  Observability
          | JSON events, Prometheus,      |  HMAC webhooks (Slack/Discord)
          +-------------------------------+
```

## Concurrency Model

sks5 is a fully async application built on **tokio** (multi-threaded runtime):

- **One task per SSH session**: Each SSH connection spawns a tokio task that owns the session lifecycle (auth, shell, forwarding channels).
- **One task per SOCKS5 connection**: Standalone SOCKS5 clients each get a dedicated task.
- **Bidirectional relay**: Proxy connections use `tokio::io::copy_bidirectional` for zero-copy forwarding between client and upstream.
- **Shared state via `Arc`**: `AppContext` holds all shared state (config, bans, quotas, metrics, persistence) behind `Arc`. Mutable state uses `Arc<RwLock<_>>` or `Arc<DashMap<_>>`.
- **Graceful shutdown**: `tokio::signal` + `CancellationToken` propagate shutdown to all tasks. A configurable `shutdown_timeout` allows in-flight connections to drain.
- **Background tasks**: Persistence flushers, alerting evaluators, and maintenance window checkers run as independent `tokio::spawn` tasks with their own intervals.

## Data Flow

```
Client ─── TCP connect ──▶ SSH/SOCKS5 Listener
                                │
                          pre_auth_check()
                           (ban, rate limit, IP reputation)
                                │
                          Authentication
                           (Argon2id / PubKey / Cert / TOTP)
                                │
                          ┌─────┴──────┐
                          ▼            ▼
                    Shell Session    Forwarding Request
                    (emulator)       (-D / -L / SOCKS5)
                                        │
                                    ACL check
                                   (CIDR, FQDN, GeoIP, anti-SSRF)
                                        │
                                    Quota check
                                   (bandwidth, connections)
                                        │
                                    ProxyEngine::connect()
                                   (pool lookup → TCP connect → relay)
                                        │
                                    ┌───┴────┐
                                    ▼        ▼
                              Audit Event  Metrics
                              (+ webhook)  (Prometheus)
```

## Key Design Decisions

### 1. Shared ProxyEngine
The `proxy/` module is the shared layer. All three paths (SSH `-D`, SSH `-L`, SOCKS5 standalone) converge to `ProxyEngine::connect()` (ACL check + TCP connect) then relay (bidirectional copy). Same code, same ACL enforcement.

### 2. Virtual Filesystem
The shell exposes NO real files. An in-memory tree (`/home/<user>`, `/etc/hostname`, etc.) prevents information leakage.

### 3. ConnectionGuard (RAII)
Connection counters auto-decrement on drop, preventing leaks.

### 4. DNS Cache (configurable)
DNS cache with configurable TTL (`dns_cache_ttl`): `-1` = system resolver, `0` = disabled, `N` = N seconds. FQDN ACL rules match the hostname string, CIDR ACL rules match the resolved IP.

### 5. SecurityManager::pre_auth_check()
Shared pre-authentication IP validation (allowlist + ban check + rate limit + IP reputation) used by both SSH and SOCKS5 handlers, eliminating code duplication.

### 6. User::is_source_ip_allowed()
Per-user source IP validation extracted into a User helper method, shared across SSH and SOCKS5 paths.

### 7. Specific SOCKS5 Reply Codes
Error replies use RFC 1928-compliant codes: `REPLY_NOT_ALLOWED` for ACL denials, `REPLY_CONNECTION_REFUSED` for refused connections, `REPLY_GENERAL_FAILURE` for other errors.

### 8. AppContext (shared state)
`context.rs` defines `AppContext`, an `Arc`-wrapped struct holding references to all shared subsystems (config, security manager, quota manager, persistence, metrics, audit, webhooks, alerting). Passed to all handlers, avoiding global state.

### 9. Persistence with Graceful Degradation
The `persistence/` module flushes state (bans, quotas, reputation, user data) to disk on configurable intervals. If the data directory is unavailable, the server continues in pure in-memory mode with a warning — persistence never blocks operation.

## Hot-Reload

sks5 supports live configuration reload without restart:

- **API**: `POST /api/reload` with Bearer token auth
- **Signal**: `SIGHUP` triggers reload
- **Scope**: Users, ACLs, groups, quotas, security settings, webhooks, alerting rules, shell config, MOTD
- **Immutable on reload**: Listen addresses (`ssh_listen`, `socks5_listen`, `api_listen`, `metrics_listen`)
- **Audit trail**: Every reload (success or failure) is logged as an audit event
- **Config history**: Before applying changes, the current config is snapshot to `{data_dir}/config-history/` for rollback

## Security Features

- **Authentication**: Argon2id password hashing, SSH public key auth, SSH certificates, TOTP 2FA, auth method chaining
- **ACL**: Per-user and global allow/deny rules (CIDR, wildcard hostname, port ranges)
- **Auto-ban**: fail2ban-like IP banning after N failed auth attempts
- **IP whitelist**: Global and per-user source IP restrictions
- **Rate limiting**: Multi-window (per-second/minute/hour), per-user and server-level
- **IP reputation**: Dynamic scoring with exponential decay, persisted across restarts
- **GeoIP filtering**: Country-based allow/deny lists
- **Anti-SSRF**: Blocks RFC 1918, link-local, loopback, multicast in proxy targets
- **Hostname validation**: SOCKS5 domain names limited to 253 chars (RFC 1035), validated per RFC 952

## Management API

- **REST API**: Bearer token auth, user/connection/ban/quota/group/session management
- **Hot-reload**: `POST /api/reload` reloads config from disk, `SIGHUP` signal support
- **WebUI Dashboard**: Real-time web interface at `/dashboard` with SSE/WebSocket live updates
- **Audit logging**: All management actions tracked in audit trail
- **Backup/Restore**: `GET /api/backup` and `POST /api/restore` for state portability

## Observability

- **Audit logging**: JSON event log (auth, proxy, ACL, bans, config reloads, kicks, broadcasts)
- **Prometheus metrics**: connections, bandwidth, auth stats, persistence stats, dropped audit events
- **Health endpoints**: `/livez` (liveness, always 200), `/readyz` (readiness, 503 in maintenance), `/api/health` (detailed)
- **SSE endpoint**: `/api/events` for real-time monitoring (HMAC ticket auth)
- **WebSocket**: `/api/ws` for real-time dashboard updates
- **Webhooks**: HTTP callbacks with HMAC signatures, retry logic, Slack/Discord/custom formats
- **Alerting**: Configurable rules on bandwidth, connections, and auth failures
