# sks5 Architecture

## Overview

sks5 is a lightweight SSH server in Rust that serves as a SOCKS5 proxy with an emulated shell. It supports three modes of forwarding:
- **Dynamic forwarding** (`ssh -D`): SOCKS5 proxy via direct-tcpip channels
- **Local port forwarding** (`ssh -L`): TCP forwarding via direct-tcpip channels
- **Standalone SOCKS5**: Dedicated listener on a separate port

## Module Architecture

```
              +----------+
              | main.rs  |  CLI (clap) + bootstrap
              |  cli.rs  |
              +----+-----+
                   |
              +----v-----+
              | server.rs |  Orchestrator (SSH + SOCKS5 + API, SIGHUP)
              +----+------+
                   |
      +-------+----+----+--------+
      |        |         |        |
 +----v----+  +v-----+  +v-----+ +v--------+
 |  ssh/   |  |socks/|  |config| |  api/   |
 | handler |  |server|  |types | |dashboard|
 +----+----+  +--+---+  +--+---+ | sse     |
      |          |          |     | reload  |
 +----v----+     |     +----v--+  +----+----+
 | shell/  |     |     | auth/ |       |
 |emulator |     |     | store |       |
 +---------+     |     +---+---+       |
                 |         |           |
          +------v---------v-----------v--+
          |         proxy/                |  Shared layer
          | forwarder + acl + connector   |  SSH, SOCKS5, API converge
          +-------------------------------+

          +-------------------------------+
          |       security/               |  Pre-auth checks, bans,
          | ban + ip_filter + pre_auth    |  rate limiting, GeoIP
          +-------------------------------+

          +-------------------------------+
          |       audit/ + metrics/       |  Observability
          | JSON events + Prometheus      |  Dropped event counter
          +-------------------------------+
```

## Key Design Decisions

### 1. Shared ProxyEngine
The `proxy/` module is the shared layer. All three paths (SSH `-D`, SSH `-L`, SOCKS5 standalone) converge to `ProxyEngine::connect()` (ACL check + TCP connect) then relay (bidirectional copy). Same code, same ACL enforcement.

### 2. Virtual Filesystem
The shell exposes NO real files. An in-memory tree (`/home/<user>`, `/etc/hostname`, etc.) prevents information leakage.

### 3. ConnectionGuard (RAII)
Connection counters auto-decrement on drop, preventing leaks.

### 4. Fresh DNS per Connection
No DNS cache in the proxy. FQDN ACL rules match the hostname string, CIDR ACL rules match the resolved IP.

### 5. SecurityManager::pre_auth_check()
Shared pre-authentication IP validation (allowlist + ban check) used by both SSH and SOCKS5 handlers, eliminating code duplication.

### 6. User::is_source_ip_allowed()
Per-user source IP validation extracted into a User helper method, shared across SSH and SOCKS5 paths.

### 7. Specific SOCKS5 Reply Codes
Error replies use RFC 1928-compliant codes: `REPLY_NOT_ALLOWED` for ACL denials, `REPLY_CONNECTION_REFUSED` for refused connections, `REPLY_GENERAL_FAILURE` for other errors.

## Security Features

- **Authentication**: Argon2id password hashing, SSH public key auth
- **ACL**: Per-user allow/deny rules (CIDR, wildcard hostname, port ranges)
- **Auto-ban**: fail2ban-like IP banning after N failed auth attempts
- **IP whitelist**: Global and per-user source IP restrictions
- **Rate limiting**: Per-user connection rate limits (token bucket)
- **GeoIP filtering**: Country-based allow/deny lists
- **Hostname validation**: SOCKS5 domain names limited to 253 chars (RFC 1035)

## Management API

- **REST API**: Bearer token auth, user/connection/ban management
- **Hot-reload**: `POST /api/reload` reloads config from disk, `SIGHUP` signal support
- **WebUI Dashboard**: Real-time web interface at `/dashboard` with SSE live updates
- **Audit logging**: Config reload events tracked in audit trail

## Observability

- **Audit logging**: JSON event log (auth, proxy, ACL, bans, config reloads)
- **Prometheus metrics**: connections, bandwidth, auth stats, dropped audit events
- **Health endpoint**: `/health` for load balancers
- **SSE endpoint**: `/api/events` for real-time monitoring
