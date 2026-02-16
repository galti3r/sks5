# sks5 User Guide

## Table of Contents

- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [First SSH Connection](#first-ssh-connection)
  - [First SOCKS5 Connection](#first-socks5-connection)
- [Configuration](#configuration)
  - [Config File Format](#config-file-format)
  - [Config Sections Overview](#config-sections-overview)
  - [Environment Variables](#environment-variables)
  - [Docker Secrets via _FILE Convention](#docker-secrets-via-_file-convention)
  - [Config Presets](#config-presets)
  - [Show Config](#show-config)
  - [Check Config](#check-config)
- [Authentication](#authentication)
  - [Password Authentication](#password-authentication)
  - [Public Key Authentication](#public-key-authentication)
  - [TOTP Two-Factor Authentication](#totp-two-factor-authentication)
  - [Auth Methods Chaining](#auth-methods-chaining)
  - [Source IP Restrictions](#source-ip-restrictions)
  - [Account Expiration](#account-expiration)
- [Access Control (ACL)](#access-control-acl)
  - [Global ACL](#global-acl)
  - [Per-User ACL](#per-user-acl)
  - [Rule Format](#rule-format)
  - [ACL Inheritance](#acl-inheritance)
  - [IP Guard](#ip-guard)
- [Shell](#shell)
  - [Built-in Shell Commands](#built-in-shell-commands)
  - [Extended Commands](#extended-commands)
  - [Bookmarks](#bookmarks)
  - [Aliases](#aliases)
  - [Shell Permissions](#shell-permissions)
  - [MOTD (Message of the Day)](#motd-message-of-the-day)
- [Monitoring](#monitoring)
  - [Prometheus Metrics](#prometheus-metrics)
  - [API Dashboard](#api-dashboard)
  - [API Endpoints](#api-endpoints)
  - [Alerting Engine](#alerting-engine)
  - [Webhooks](#webhooks)
- [Quotas and Rate Limiting](#quotas-and-rate-limiting)
  - [Per-User Quotas](#per-user-quotas)
  - [Rate Limits](#rate-limits)
  - [Bandwidth Limits](#bandwidth-limits)
  - [Total Bytes Tracking](#total-bytes-tracking)
- [Troubleshooting](#troubleshooting)
  - [Common Errors and Solutions](#common-errors-and-solutions)
  - [Debug Logging](#debug-logging)
  - [Health Check](#health-check)

---

## Getting Started

### Installation

**From source (recommended):**

```bash
git clone https://github.com/galti3r/sks5.git
cd sks5
cargo build --release
# Binary is at target/release/sks5
```

**Using cargo install:**

```bash
cargo install --path .
# Binary installed to ~/.cargo/bin/sks5
```

**Static binary (musl):**

```bash
make build-static
# Binary is at target/<arch>-unknown-linux-musl/release/sks5
```

**Docker / Podman:**

```bash
# Build the Alpine image (default)
podman build -f Containerfile.alpine -t sks5:latest .

# Build the scratch image (minimal)
podman build -t sks5:scratch .

# Or with Docker
docker build -f Containerfile.alpine -t sks5:latest .
```

### Quick Start

The fastest way to get sks5 running is the `quick-start` command. It generates an in-memory configuration and starts the server immediately with zero setup:

```bash
# Start with a specific password
sks5 quick-start --password demo

# Start with a custom username
sks5 quick-start --username alice --password mysecret

# Start with an auto-generated password (printed to stdout)
sks5 quick-start

# Enable standalone SOCKS5 listener
sks5 quick-start --password demo --socks5-listen 0.0.0.0:1080

# Save the generated configuration for future use
sks5 quick-start --password demo --save-config config.toml
```

### First SSH Connection

Once sks5 is running (default port 2222), connect with an SSH client:

```bash
# Basic SSH connection (interactive shell)
ssh -o StrictHostKeyChecking=no user@localhost -p 2222

# Dynamic SOCKS5 forwarding (creates a SOCKS5 proxy on local port 8080)
ssh -D 8080 -o StrictHostKeyChecking=no user@localhost -p 2222

# Local port forwarding (forward local:3000 to remote-host:80)
ssh -L 3000:remote-host:80 -o StrictHostKeyChecking=no user@localhost -p 2222
```

You can also generate an SSH config snippet for convenient access:

```bash
sks5 ssh-config --user alice --host myserver.example.com --port 2222 --name sks5-proxy
```

### First SOCKS5 Connection

If you have enabled the standalone SOCKS5 listener (`socks5_listen` in config or `--socks5-listen` in quick-start), you can connect directly:

```bash
# HTTP request through SOCKS5 proxy
curl --socks5 user:pass@localhost:1080 http://example.com

# HTTPS through SOCKS5
curl --socks5-hostname user:pass@localhost:1080 https://api.github.com

# Using with Firefox/Chrome: set SOCKS5 proxy to localhost:1080
```

When using the SSH dynamic forwarding mode (`ssh -D`), the SOCKS5 proxy runs on your local machine through the SSH tunnel:

```bash
# Start SSH dynamic forwarding
ssh -D 8080 -N user@localhost -p 2222

# Then use the local SOCKS5 proxy
curl --socks5-hostname localhost:8080 http://example.com
```

---

## Configuration

### Config File Format

sks5 uses TOML for configuration. The default config file path is `config.toml`, overridable via `--config` flag or `SKS5_CONFIG` environment variable.

```bash
# Use a specific config file
sks5 --config /etc/sks5/config.toml

# Use SKS5_CONFIG env var
SKS5_CONFIG=/etc/sks5/config.toml sks5
```

Only two sections are required:
- `[server]` with `ssh_listen` address
- At least one `[[users]]` entry with authentication credentials

All other sections are optional and have sensible defaults.

### Config Sections Overview

| Section | Purpose |
|---------|---------|
| `[server]` | SSH/SOCKS5 listen addresses, host key, TLS, DNS cache, proxy protocol |
| `[shell]` | Shell emulator settings (hostname, prompt, colors, autocomplete) |
| `[limits]` | Connection limits, timeouts, bandwidth caps, rate limits |
| `[security]` | IP filtering, auto-banning, IP reputation, TOTP enforcement, GeoIP |
| `[logging]` | Log level, format, audit log path, rotation |
| `[metrics]` | Prometheus metrics endpoint configuration |
| `[api]` | Management API server (REST, SSE, WebSocket, dashboard) |
| `[geoip]` | GeoIP-based country filtering |
| `[acl]` | Global access control lists (allow/deny rules) |
| `[motd]` | Message of the Day template with variables |
| `[upstream_proxy]` | Route outbound traffic through an upstream SOCKS5 proxy |
| `[alerting]` | Alert rules for bandwidth, connections, auth failures |
| `[connection_pool]` | TCP connection pooling for outbound connections |
| `[[users]]` | User definitions (auth, ACL, quotas, permissions) |
| `[[groups]]` | Group definitions for shared user configuration |
| `[[webhooks]]` | HTTP webhooks for event notifications |
| `[[maintenance_windows]]` | Scheduled maintenance periods |

See [CONFIG-REFERENCE.md](CONFIG-REFERENCE.md) for the complete field-by-field reference.

### Environment Variables

sks5 supports three configuration modes:

**Mode 1: Config file path via environment variable**

```bash
SKS5_CONFIG=/etc/sks5/config.toml sks5
```

**Mode 2: Full configuration from environment variables (no config file needed)**

Requires at minimum `SKS5_SSH_LISTEN` and authentication credentials. Single-user mode:

```bash
SKS5_SSH_LISTEN=0.0.0.0:2222 \
SKS5_PASSWORD_HASH='$argon2id$...' \
SKS5_USERNAME=alice \
SKS5_SOCKS5_LISTEN=0.0.0.0:1080 \
sks5
```

Multi-user indexed mode (use `SKS5_USER_<N>_*` pattern, N=0,1,2...):

```bash
SKS5_SSH_LISTEN=0.0.0.0:2222 \
SKS5_USER_0_USERNAME=alice \
SKS5_USER_0_PASSWORD_HASH='$argon2id$...' \
SKS5_USER_0_ALLOW_SHELL=true \
SKS5_USER_1_USERNAME=bob \
SKS5_USER_1_PASSWORD_HASH='$argon2id$...' \
SKS5_USER_1_ALLOW_SHELL=false \
sks5
```

The indexed sequence stops at the first missing index. If `SKS5_USER_0_USERNAME` is set, flat vars like `SKS5_USERNAME` are ignored.

**Mode 3: Hybrid (config file + environment variable overrides)**

Load a config file and override specific values with environment variables:

```bash
SKS5_LOG_LEVEL=debug \
SKS5_API_TOKEN=secret-from-env \
SKS5_BAN_THRESHOLD=10 \
sks5 --config config.toml
```

**Key environment variables:**

| Variable | Description |
|----------|-------------|
| `SKS5_CONFIG` | Config file path |
| `SKS5_SSH_LISTEN` | SSH listen address |
| `SKS5_SOCKS5_LISTEN` | Standalone SOCKS5 listen address |
| `SKS5_HOST_KEY_PATH` | SSH host key file path |
| `SKS5_LOG_LEVEL` | Log level (trace/debug/info/warn/error) |
| `SKS5_LOG_FORMAT` | Log format (pretty/json) |
| `SKS5_MAX_CONNECTIONS` | Max total connections |
| `SKS5_CONNECTION_TIMEOUT` | Connection timeout (seconds) |
| `SKS5_IDLE_TIMEOUT` | Idle timeout (seconds) |
| `SKS5_BAN_ENABLED` | Enable auto-banning (true/false) |
| `SKS5_BAN_THRESHOLD` | Failed auth attempts before ban |
| `SKS5_IP_GUARD_ENABLED` | Block private IP connections (true/false) |
| `SKS5_METRICS_ENABLED` | Enable Prometheus metrics (true/false) |
| `SKS5_METRICS_LISTEN` | Metrics listen address |
| `SKS5_API_ENABLED` | Enable management API (true/false) |
| `SKS5_API_LISTEN` | API listen address |
| `SKS5_API_TOKEN` | API bearer token |
| `SKS5_GLOBAL_ACL_DEFAULT_POLICY` | Global ACL policy (allow/deny) |
| `SKS5_GLOBAL_ACL_DENY` | Comma-separated global deny rules |
| `SKS5_GLOBAL_ACL_ALLOW` | Comma-separated global allow rules |
| `SKS5_USERNAME` | Single-user username (default: "user") |
| `SKS5_PASSWORD_HASH` | Single-user password hash |
| `SKS5_AUTHORIZED_KEYS` | Comma-separated SSH public keys |

Per-user indexed variables follow the pattern `SKS5_USER_<N>_<FIELD>`:

| Variable Pattern | Description |
|-----------------|-------------|
| `SKS5_USER_<N>_USERNAME` | Username |
| `SKS5_USER_<N>_PASSWORD_HASH` | Password hash |
| `SKS5_USER_<N>_AUTHORIZED_KEYS` | Comma-separated SSH public keys |
| `SKS5_USER_<N>_ALLOW_FORWARDING` | Allow SOCKS5/port forwarding |
| `SKS5_USER_<N>_ALLOW_SHELL` | Allow interactive shell |
| `SKS5_USER_<N>_MAX_BANDWIDTH_KBPS` | Per-connection bandwidth limit |
| `SKS5_USER_<N>_SOURCE_IPS` | Comma-separated allowed source CIDRs |
| `SKS5_USER_<N>_ACL_DEFAULT_POLICY` | Per-user ACL policy |
| `SKS5_USER_<N>_ACL_ALLOW` | Comma-separated user allow rules |
| `SKS5_USER_<N>_ACL_DENY` | Comma-separated user deny rules |
| `SKS5_USER_<N>_TOTP_ENABLED` | Enable TOTP 2FA |
| `SKS5_USER_<N>_TOTP_SECRET` | TOTP secret (base32) |

### Docker Secrets via _FILE Convention

For sensitive values, sks5 supports the `_FILE` suffix convention used by Docker and Kubernetes secrets. Instead of setting the value directly, point to a file containing the secret:

```bash
# Instead of:
SKS5_API_TOKEN=my-secret-token

# Use:
SKS5_API_TOKEN_FILE=/run/secrets/api_token
```

The file content is read and trimmed (leading/trailing whitespace removed). If both the direct variable and the `_FILE` variant are set, the direct variable takes priority.

Supported `_FILE` variables:
- `SKS5_PASSWORD_HASH_FILE`
- `SKS5_API_TOKEN_FILE`
- `SKS5_TOTP_SECRET_FILE`
- `SKS5_USER_<N>_PASSWORD_HASH_FILE`
- `SKS5_USER_<N>_TOTP_SECRET_FILE`

### Config Presets

Generate a config file using presets tailored for common use cases:

```bash
# Bastion host preset (strict security, audit logging)
sks5 init --preset bastion --username admin --password mysecret --output config.toml

# SOCKS5 proxy preset (forwarding-focused, relaxed shell)
sks5 init --preset proxy --username proxyuser --password secret --output config.toml

# Development preset (permissive, debug logging)
sks5 init --preset dev --username dev --password dev --output config.toml

# Default (no preset)
sks5 init --username alice --password secret --output config.toml
```

### Show Config

Display the effective configuration (with sensitive fields like password hashes and tokens redacted):

```bash
# Show as TOML (default)
sks5 show-config

# Show as JSON
sks5 show-config --format json

# From a specific config file
sks5 --config /etc/sks5/config.toml show-config
```

### Check Config

Validate a configuration file without starting the server:

```bash
sks5 check-config
sks5 --config /etc/sks5/config.toml check-config
```

This checks for:
- TOML syntax errors
- Missing required fields
- Invalid values (e.g., empty `ssh_listen`, `ban_threshold` = 0 with banning enabled)
- Duplicate usernames
- API token presence when API is enabled
- Reference integrity (users referencing non-existent groups)

---

## Authentication

### Password Authentication

sks5 uses Argon2id for password hashing, the current recommended algorithm for password storage. Passwords are never stored in plaintext.

**Generate a password hash:**

```bash
# Interactive (prompted)
sks5 hash-password

# Non-interactive
sks5 hash-password --password "my-strong-password"

# Using the Makefile
make hash-password
```

**Configure in TOML:**

```toml
[[users]]
username = "alice"
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$randomsalt$derivedhash"
```

### Public Key Authentication

Users can authenticate with SSH public keys instead of or in addition to passwords:

```toml
[[users]]
username = "charlie"
authorized_keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... charlie@laptop",
    "ssh-rsa AAAAB3NzaC1yc2EAAAA... charlie@desktop",
]
```

Connect using key-based auth:

```bash
ssh -i ~/.ssh/id_ed25519 -p 2222 charlie@localhost
```

### TOTP Two-Factor Authentication

sks5 supports Time-based One-Time Passwords (TOTP) as a second factor. When enabled, users must append a 6-digit TOTP code to their password.

**Step 1: Generate a TOTP secret**

```bash
sks5 generate-totp --username alice
```

This outputs a base32 secret and an `otpauth://` URI that can be scanned as a QR code in apps like Google Authenticator, Authy, or 1Password.

**Step 2: Configure the user**

```toml
[[users]]
username = "alice"
password_hash = "$argon2id$..."
totp_enabled = true
totp_secret = "JBSWY3DPEHPK3PXP"  # base32 secret from step 1
```

**Step 3: Authenticate**

When logging in, append the current 6-digit TOTP code to the password:

```
Password: mypassword123456
           ^^^^^^^^^^ ^^^^^^
           password   TOTP code
```

For SOCKS5 standalone connections, the same convention applies:

```bash
curl --socks5 alice:mypassword123456@localhost:1080 http://example.com
```

**Global TOTP enforcement:**

You can require TOTP for specific protocols:

```toml
[security]
totp_required_for = ["ssh", "socks5"]
```

### Auth Methods Chaining

Require users to authenticate with multiple methods in sequence:

```toml
[[users]]
username = "secure-user"
password_hash = "$argon2id$..."
authorized_keys = ["ssh-ed25519 AAAA..."]
auth_methods = ["pubkey", "password"]  # Both required, in order
```

### Source IP Restrictions

Restrict which IP addresses a user can connect from:

```toml
[[users]]
username = "office-user"
password_hash = "$argon2id$..."
source_ips = ["10.0.0.0/8", "192.168.1.0/24"]
```

Connections from IPs outside these ranges are rejected before authentication.

### Account Expiration

Set an expiration date after which the account is disabled:

```toml
[[users]]
username = "contractor"
password_hash = "$argon2id$..."
expires_at = "2026-12-31T23:59:59Z"
```

After the expiration date, all authentication attempts are rejected.

---

## Access Control (ACL)

### Global ACL

The global ACL applies to all users. It defines a default policy and allow/deny rules:

```toml
[acl]
default_policy = "allow"  # "allow" or "deny"
deny = [
    "169.254.169.254:*",   # Block cloud metadata
    "10.0.0.0/8:*",        # Block internal networks
    "172.16.0.0/12:*",
    "192.168.0.0/16:*",
]
allow = []
```

When `default_policy` is `"allow"`, all destinations are allowed unless explicitly denied. When set to `"deny"`, all destinations are blocked unless explicitly allowed (whitelist mode).

### Per-User ACL

Each user can have additional ACL rules that are merged with the global ACL:

```toml
[users.acl]
default_policy = "deny"  # Override global policy for this user
inherit = true           # Merge with global rules (default: true)
allow = [
    "*.example.com:443",
    "api.github.com:443",
]
deny = [
    "evil.com:*",
]
```

### Rule Format

ACL rules follow the format `target:port` where:

| Pattern | Example | Matches |
|---------|---------|---------|
| Exact host | `example.com:443` | Only example.com on port 443 |
| Wildcard domain | `*.example.com:443` | Any subdomain of example.com on port 443 |
| CIDR subnet | `10.0.0.0/8:80` | Any IP in 10.0.0.0/8 on port 80 |
| Port range | `example.com:80-443` | Ports 80 through 443 |
| All ports | `example.com:*` | All ports on example.com |
| All destinations | `*:*` | Everything |
| IPv6 | `[2606:2800:220:1::]:443` | Specific IPv6 address on port 443 |

### ACL Inheritance

The `inherit` flag controls how per-user ACL rules interact with global rules:

- `inherit = true` (default): User's allow/deny rules are **merged** with global rules. User's `default_policy` overrides the global one if set.
- `inherit = false`: Global ACL is completely ignored for this user. Only the user's own rules apply.

**Evaluation order:**
1. Deny rules are checked first (global deny + user deny when inheriting)
2. Allow rules are checked next (global allow + user allow when inheriting)
3. Default policy is applied if no rule matches

### IP Guard

The IP Guard is an anti-SSRF defense that prevents forwarding connections to private and internal IP addresses. It blocks:

- `127.0.0.0/8` (loopback)
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918)
- `169.254.0.0/16` (link-local)
- `fc00::/7`, `fe80::/10` (IPv6 private/link-local)
- `::1` (IPv6 loopback)
- Cloud metadata endpoints (e.g., `169.254.169.254`)

IP Guard is enabled by default. Disable it only if you need to forward to internal networks:

```toml
[security]
ip_guard_enabled = false
```

### ACL: Hostname vs IP Blocking

**Important security consideration:** ACL rules using hostname patterns (e.g., `www.google.fr:*`, `*.example.com:443`) only match the hostname as provided in the SOCKS5/SSH forwarding request. They do **not** perform reverse DNS lookups or IP-to-hostname resolution.

This means if a user sends a connection request with the raw IP address (e.g., `142.250.x.x:443`) instead of the hostname, a hostname-based deny rule like `www.google.fr:*` will **not** block the connection. The ACL has two evaluation phases:

1. **Pre-check (hostname):** Rules of type `HostPattern` match the hostname string from the request
2. **Post-check (IP):** Rules of type `Cidr` match the resolved IP address after DNS resolution

A `HostPattern` rule never matches a raw IP request, and a `Cidr` rule never matches a hostname request at the pre-check phase (it matches at post-check).

**Mitigations:**

- **Use `default_policy = "deny"` with an allowlist** (recommended): Only permit explicitly allowed destinations. This is the most secure approach.
- **Combine hostname and CIDR rules:** Add both `www.google.fr:*` and the corresponding IP ranges (e.g., `142.250.0.0/16:*`) to your deny list.
- **Enable IP Guard:** The built-in IP Guard blocks connections to private/internal IP ranges regardless of how the request is made.

```toml
# Secure: deny-by-default with allowlist
[users.acl]
default_policy = "deny"
allow = [
    "api.github.com:443",
    "*.example.com:443",
]
```

---

## Shell

sks5 includes a built-in shell emulator that provides a familiar interactive experience without exposing any real system files or processes. The shell uses a virtual filesystem.

### Built-in Shell Commands

These commands are always available:

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `ls [path]` | List files in virtual filesystem |
| `cd [path]` | Change directory |
| `pwd` | Print working directory |
| `cat <file>` | Display file contents |
| `whoami` | Print current username |
| `uname [-a]` | Print system information |
| `hostname` | Print hostname |
| `id` | Print user/group identity |
| `echo <text>` | Print text |
| `env` / `printenv` | Print environment variables |
| `clear` | Clear the terminal screen |
| `exit` / `logout` | End the session |

### Extended Commands

These commands require an active shell context with proxy engine access:

| Command | Description |
|---------|-------------|
| `show connections` | Display active proxy connections |
| `show bandwidth` | Display bandwidth usage statistics |
| `show acl` | Display effective ACL rules |
| `show status` | Display session information (user, IP, role) |
| `show history` | Display command history |
| `show fingerprint` | Display SSH key fingerprint |
| `test <host:port>` | Test TCP connectivity to a destination |
| `ping <host>` | Simulated ICMP-like ping to a host |
| `resolve <hostname>` | Perform DNS lookup for a hostname |
| `bookmark <subcommand>` | Manage host bookmarks |
| `alias <subcommand>` | Manage command aliases |

### Bookmarks

Bookmarks provide quick access to frequently used destinations:

```
# Add a bookmark
bookmark add prod-db production-db.internal:5432

# List all bookmarks
bookmark list

# Delete a bookmark
bookmark del prod-db

# Connect to a bookmarked destination (test connectivity)
test prod-db
```

Bookmarks are stored in-memory by default. To persist them across restarts, configure a storage path:

```toml
[server]
bookmarks_path = "/var/lib/sks5/bookmarks.json"
```

### Aliases

Aliases let users define shortcut commands:

**In config file:**

```toml
[users.aliases]
db = "test prod-db:5432"
web = "test web-app:443"
status = "show status"
```

**In shell at runtime:**

```
# Add an alias
alias add mydb "test database:5432"

# List aliases
alias list

# Delete an alias
alias del mydb

# Use an alias (just type the alias name)
mydb
```

### Shell Permissions

Each shell command can be individually enabled or disabled per user or per group:

```toml
[users.shell_permissions]
show_connections = true    # show connections
show_bandwidth = true      # show bandwidth
show_acl = true            # show acl
show_status = true         # show status
show_history = true        # show history
show_fingerprint = true    # show fingerprint
test_command = true        # test host:port
ping_command = true        # ping host
resolve_command = true     # resolve hostname
bookmark_command = true    # bookmark add/list/del
alias_command = true       # alias add/list/del
show_quota = true             # show quota
show_role = true              # MOTD {role} + show status role line
show_group = true             # MOTD {group} + show status group line
show_expires = true           # MOTD {expires_at} + show status expires line
show_source_ip = true         # MOTD {source_ip} + show status source line
show_auth_method = true       # MOTD {auth_method} + show status auth line
show_uptime = true            # MOTD {uptime} + show status uptime line
```

All permissions default to `true`. Set to `false` to restrict access.

These permissions control both the shell commands and the MOTD template. When a permission is set to `false`, the corresponding MOTD placeholder is replaced with an empty string (the line is hidden in the default template), and the matching shell command or `show status` line is also hidden.

### MOTD (Message of the Day)

The MOTD is displayed after successful SSH login. It supports template variables:

```toml
[motd]
enabled = true
colors = true
template = """
Welcome {user}! Connected from {source_ip} via {auth_method}.
Role: {role} | Group: {group} | Policy: {acl_policy}
Bandwidth: {bandwidth_used} / {bandwidth_limit}
Server uptime: {uptime} | Version: {version}
"""
```

**Available template variables:**

| Variable | Description |
|----------|-------------|
| `{user}` | Username |
| `{auth_method}` | Authentication method used |
| `{source_ip}` | Client IP address |
| `{connections}` | Number of active connections for this user |
| `{acl_policy}` | Effective ACL policy ("allow" or "deny") |
| `{expires_at}` | Account expiration date or "never" |
| `{bandwidth_used}` | Total bandwidth consumed (human-readable) |
| `{bandwidth_limit}` | Bandwidth limit or "unlimited" |
| `{last_login}` | Last login timestamp or "first login" |
| `{uptime}` | Server uptime (human-readable) |
| `{version}` | sks5 version string |
| `{group}` | Group name or "none" |
| `{role}` | "user" or "admin" |
| `{denied}` | Comma-separated ACL deny rules or "none" |
| `{allowed}` | Comma-separated ACL allow rules or "none" |

MOTD can be overridden per group or per user. Inheritance order: user > group > global.

MOTD visibility is controlled by `[users.shell_permissions]` flags. When a flag like `show_acl = false` is set, the corresponding MOTD placeholders (`{acl_policy}`, `{allowed}`, `{denied}`) are replaced with empty strings, and the lines are automatically hidden in the default template.

---

## Monitoring

### Prometheus Metrics

Enable the Prometheus-compatible metrics endpoint:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9090"
max_metric_labels = 100
```

Access metrics at `http://127.0.0.1:9090/metrics`. Additional endpoints on the metrics server:

| Endpoint | Description |
|----------|-------------|
| `GET /metrics` | Prometheus metrics (text format) |
| `GET /health` | Health check (200 OK or 503 during maintenance) |
| `GET /livez` | Liveness probe (always 200) |

### API Dashboard

The management API includes a real-time web dashboard:

```toml
[api]
enabled = true
listen = "127.0.0.1:9091"
token = "my-secret-api-token"
```

Access the dashboard at `http://127.0.0.1:9091/dashboard?token=my-secret-api-token`.

The dashboard provides real-time updates via Server-Sent Events (SSE) and WebSocket connections. SSE connections use an HMAC-based ticket system for authentication:

1. Obtain a ticket: `POST /api/sse-ticket` (requires Bearer auth)
2. Connect to SSE: `GET /api/events?ticket=<ticket>` (ticket valid for 30 seconds)

### API Endpoints

All API endpoints require authentication via `Authorization: Bearer <token>` header (except `/livez` and `/api/health`). Alternatively, use `?token=<token>` query parameter for browser access.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health status with details (maintenance, connections, uptime) |
| GET | `/api/status` | Server status (uptime, active connections, total users) |
| GET | `/api/users` | List all configured users |
| GET | `/api/users/{username}` | Get detailed information for a specific user |
| GET | `/api/connections` | List active proxy connections |
| GET | `/api/bans` | List currently banned IPs |
| DELETE | `/api/bans/{ip}` | Remove a specific IP ban |
| GET | `/api/quotas` | List quota usage for all users |
| GET | `/api/quotas/:username` | Get quota usage for a specific user |
| POST | `/api/quotas/:username/reset` | Reset quota counters for a user |
| GET | `/api/groups` | List all configured groups |
| GET | `/api/groups/:name` | Get details for a specific group |
| GET | `/api/sessions` | List active SSH sessions |
| GET | `/api/sessions/:username` | Get sessions for a specific user |
| POST | `/api/maintenance` | Toggle maintenance mode |
| POST | `/api/reload` | Reload configuration from disk |
| POST | `/api/broadcast` | Broadcast a message to all connected users |
| POST | `/api/kick/{username}` | Disconnect a specific user |
| GET | `/api/ssh-config` | Generate SSH config snippet |
| POST | `/api/sse-ticket` | Issue an HMAC ticket for SSE authentication |
| GET | `/api/events` | Server-Sent Events stream (real-time updates) |
| GET | `/api/ws` | WebSocket connection for real-time updates |
| GET | `/api/backup` | Export server state (bans, quotas) |
| POST | `/api/restore` | Import server state from backup |
| GET | `/dashboard` | Web dashboard UI |
| GET | `/livez` | Liveness probe (unauthenticated, always 200) |

All API responses use a consistent JSON envelope:

```json
{
  "success": true,
  "data": { ... },
  "error": null
}
```

### Alerting Engine

Define alert rules that trigger when thresholds are exceeded:

```toml
[alerting]
enabled = true

[[alerting.rules]]
name = "high_bandwidth"
condition = "bandwidth_exceeded"
threshold = 1073741824  # 1 GB
window_secs = 3600      # 1 hour
users = []              # Empty = all users
webhook_url = "https://hooks.example.com/alert"

[[alerting.rules]]
name = "brute_force"
condition = "auth_failures"
threshold = 50
window_secs = 300

[[alerting.rules]]
name = "connection_spike"
condition = "connections_exceeded"
threshold = 500
window_secs = 60
```

**Condition types:**
- `bandwidth_exceeded` -- triggers when bandwidth in the window exceeds threshold bytes
- `connections_exceeded` -- triggers when connection count in the window exceeds threshold
- `auth_failures` -- triggers when authentication failures exceed threshold (server-wide)
- `monthly_bandwidth_exceeded` -- triggers when monthly cumulative bandwidth exceeds threshold bytes
- `hourly_bandwidth_exceeded` -- triggers when hourly rolling bandwidth exceeds threshold bytes

### Webhooks

Webhooks deliver HTTP POST notifications when server events occur. Supports native **Slack**, **Discord**, and **custom template** formats.

```toml
# Generic webhook (default JSON payload)
[[webhooks]]
url = "https://hooks.example.com/sks5"
events = ["auth_success", "auth_failure", "connection_open", "connection_close", "ban"]
secret = "hmac-secret-for-verification"
max_retries = 3

# Slack webhook (Block Kit format)
[[webhooks]]
url = "https://hooks.slack.com/services/T.../B.../xxx"
format = "slack"
events = ["auth_failure", "ban"]

# Discord webhook (Embed format with color-coded severity)
[[webhooks]]
url = "https://discord.com/api/webhooks/123/abc"
format = "discord"
events = ["auth_success", "auth_failure", "ban"]

# Custom template
[[webhooks]]
url = "https://hooks.example.com/custom"
format = "custom"
template = '{"alert": "{event_type}", "user": "{username}", "ip": "{source_ip}", "summary": "{summary}"}'
events = ["auth_failure"]
```

**Webhook formats:**
- `generic` (default) -- raw JSON payload with `event_type`, `timestamp`, and `data` fields
- `slack` -- Slack Block Kit with emoji per event type and structured fields
- `discord` -- Discord embed with color-coded severity (red=deny, green=success, yellow=warning, blue=info)
- `custom` -- User-defined template with placeholder substitution: `{event_type}`, `{timestamp}`, `{username}`, `{source_ip}`, `{target_host}`, `{data_json}`, `{summary}`

**Event types:**
- `auth_success` / `auth_failure` -- authentication events
- `connection_open` / `connection_close` / `proxy_complete` -- proxy connection lifecycle
- `ban` / `unban` -- IP ban events
- `config_reload` -- configuration reload
- `maintenance_start` / `maintenance_end` -- maintenance mode transitions
- `rate_limited` -- rate limit triggered
- `quota_exceeded` -- quota limit reached
- `alert_triggered` -- alerting rule fired

When a `secret` is configured, the webhook payload includes an `X-Signature-256` header containing an HMAC-SHA256 signature for verification. HMAC is computed on the final formatted body.

Retry policy uses exponential backoff: the initial delay doubles on each attempt, capped at `max_retry_delay_ms`.

---

## Quotas and Rate Limiting

### Per-User Quotas

Set usage limits that reset on daily or monthly boundaries:

```toml
[users.quotas]
daily_bandwidth_bytes = 1073741824    # 1 GB per day
daily_connection_limit = 1000         # 1000 connections per day
monthly_bandwidth_bytes = 32212254720 # 30 GB per month
monthly_connection_limit = 10000      # 10000 connections per month
bandwidth_per_hour_bytes = 536870912  # 512 MB per hour (rolling window)
total_bandwidth_bytes = 107374182400  # 100 GB lifetime (never resets)
```

Set any value to `0` for unlimited. Quotas can be configured at user level or group level. User settings override group settings.

Manage quotas via the API:

```bash
# View all quotas
curl -H "Authorization: Bearer $TOKEN" http://localhost:9091/api/quotas

# View specific user
curl -H "Authorization: Bearer $TOKEN" http://localhost:9091/api/quotas/alice

# Reset a user's quota counters
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9091/api/quotas/alice/reset
```

### Rate Limits

Control how many new connections a user can establish within time windows:

**Server-level rate limits** (apply to all connections combined):

```toml
[limits]
max_new_connections_per_second = 100
max_new_connections_per_minute = 1000
```

**Per-user legacy rate limit:**

```toml
[[users]]
max_new_connections_per_minute = 30
```

**Per-user multi-window rate limits:**

```toml
[users.rate_limits]
connections_per_second = 5
connections_per_minute = 60
connections_per_hour = 500
```

**Per-group rate limits** (inherited by group members unless overridden):

```toml
[groups.rate_limits]
connections_per_second = 5
connections_per_minute = 60
connections_per_hour = 500
```

**Pre-authentication IP-based rate limit:**

```toml
[security]
max_new_connections_per_ip_per_minute = 30
```

### Bandwidth Limits

**Per-connection bandwidth cap** (Kbps):

```toml
[[users]]
max_bandwidth_kbps = 1024  # 1 Mbps per connection
```

**Per-user aggregate bandwidth cap** (across all concurrent connections, Kbps):

```toml
[[users]]
max_aggregate_bandwidth_kbps = 4096  # 4 Mbps total
```

**Server-wide bandwidth cap** (Mbps):

```toml
[limits]
max_bandwidth_mbps = 100  # 100 Mbps total across all users
```

### Total Bytes Tracking

The `total_bandwidth_bytes` quota field tracks lifetime bandwidth usage that never auto-resets. This is useful for prepaid or metered accounts:

```toml
[users.quotas]
total_bandwidth_bytes = 107374182400  # 100 GB lifetime limit
```

Once the limit is reached, new connections are denied until an administrator resets the quota via the API.

---

## Troubleshooting

### Common Errors and Solutions

**"Connection refused" on port 2222**
- Verify sks5 is running: `sks5 health-check --addr 127.0.0.1:2222`
- Check if the port is in use: `ss -tlnp | grep 2222`
- Verify the `ssh_listen` address in config

**"Permission denied" during SSH login**
- Verify the password hash: `sks5 hash-password --password yourpass` and compare
- Check if the account is expired (`expires_at` field)
- Check source IP restrictions (`source_ips` field)
- Check if the IP is banned: `curl -H "Authorization: Bearer $TOKEN" http://localhost:9091/api/bans`

**"Connection not allowed" when forwarding**
- Check ACL rules: `show acl` in the shell
- Check if `allow_forwarding = true` for the user
- Check IP Guard (`ip_guard_enabled`) if connecting to private IPs
- Verify the ACL rule format matches your destination

**TOTP code rejected**
- Verify the system clock is synchronized (TOTP is time-sensitive)
- Ensure the TOTP code is appended directly after the password with no separator
- Regenerate the TOTP secret if the original was lost

**API returns 401 Unauthorized**
- Verify the token: `Authorization: Bearer <token>` header
- Check that the token in config matches what you are sending
- `/livez` does not require auth -- use it to verify the API server is running

**Config validation fails**
- Run `sks5 check-config` for detailed error messages
- Ensure at least one user has a `password_hash` or `authorized_keys`
- Verify `ssh_listen` is not empty
- If API is enabled, ensure `token` is set

### Debug Logging

Enable debug or trace logging for detailed diagnostics:

```bash
# Via CLI flag
sks5 --log-level debug --config config.toml

# Via environment variable
SKS5_LOG_LEVEL=debug sks5

# Trace level (most verbose)
sks5 --log-level trace
```

For structured logging (useful with log aggregators):

```toml
[logging]
level = "debug"
format = "json"
```

Enable connection flow logs for detailed per-connection timing:

```toml
[logging]
connection_flow_logs = true
```

**Suppress denied connection logs:**

If your server receives a high volume of rejected connections (bots, scanners), you can suppress the associated log messages while still recording metrics:

```toml
[logging]
log_denied_connections = false
```

When set to `false`, policy denial messages (ACL deny, rate limit exceeded, quota exceeded, banned IP, auth failed, etc.) are not logged. Metrics and audit events are still recorded normally. Default: `true`.

### Health Check

Verify the server is reachable with a TCP connect probe:

```bash
# Default (127.0.0.1:2222, 5-second timeout)
sks5 health-check

# Custom address and timeout
sks5 health-check --addr 10.0.0.1:2222 --timeout 3
```

The health check performs a TCP connection to the specified address and exits with code 0 on success, non-zero on failure. It is used in the Docker/Podman `HEALTHCHECK` directive and can be used in monitoring scripts.

Additional health endpoints when metrics or API servers are enabled:

| Endpoint | Server | Auth Required | Description |
|----------|--------|---------------|-------------|
| `/livez` | Metrics, API | No | Liveness probe (always 200) |
| `/health` | Metrics | No | Readiness probe (503 during maintenance) |
| `/api/health` | API | Yes | Detailed health with connection count and uptime |
