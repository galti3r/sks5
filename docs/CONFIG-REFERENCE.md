# sks5 Configuration Reference

Complete reference for all configuration fields in `config.toml`. Only `[server]` (with `ssh_listen`) and at least one `[[users]]` entry are required. All other sections are optional with sensible defaults.

Generate a working config quickly:

```bash
sks5 quick-start --password demo --save-config config.toml
sks5 init --username alice --password secret --output config.toml
```

---

## Table of Contents

- [\[server\]](#server)
- [\[shell\]](#shell)
- [\[limits\]](#limits)
- [\[security\]](#security)
- [\[logging\]](#logging)
- [\[metrics\]](#metrics)
- [\[api\]](#api)
- [\[geoip\]](#geoip)
- [\[motd\]](#motd)
- [\[acl\]](#acl)
- [\[upstream\_proxy\]](#upstream_proxy)
- [\[connection\_pool\]](#connection_pool)
- [\[\[users\]\]](#users)
- [\[users.acl\]](#usersacl)
- [\[users.shell\_permissions\]](#usersshell_permissions)
- [\[users.motd\]](#usersmotd)
- [\[users.quotas\]](#usersquotas)
- [\[users.time\_access\]](#userstime_access)
- [\[users.rate\_limits\]](#usersrate_limits)
- [\[\[groups\]\]](#groups)
- [\[groups.acl\]](#groupsacl)
- [\[groups.shell\_permissions\]](#groupsshell_permissions)
- [\[groups.motd\]](#groupsmotd)
- [\[groups.quotas\]](#groupsquotas)
- [\[groups.time\_access\]](#groupstime_access)
- [\[groups.rate\_limits\]](#groupsrate_limits)
- [\[\[webhooks\]\]](#webhooks)
- [\[alerting\]](#alerting)
- [\[\[alerting.rules\]\]](#alertingrules)
- [\[\[maintenance\_windows\]\]](#maintenance_windows)

---

## [server]

Core server configuration. **Required section.**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `ssh_listen` | string | _(required)_ | SSH listen address and port (e.g., `"0.0.0.0:2222"`). Cannot be empty. |
| `socks5_listen` | string? | `null` | Standalone SOCKS5 listener address (e.g., `"0.0.0.0:1080"`). Disabled when absent. Requires at least one user with a password. |
| `host_key_path` | string | `"host_key"` | Path to the SSH Ed25519 host key file. Auto-generated on first start if it does not exist. |
| `server_id` | string | `"SSH-2.0-sks5_<version>"` | SSH protocol identification string sent to clients. |
| `banner` | string | `"Welcome to sks5"` | Banner text shown before SSH authentication prompt. |
| `motd_path` | string? | `null` | Path to a raw-text Message Of The Day file (shown after login). See also `[motd]` for template-based MOTD. |
| `allowed_ciphers` | string[] | `[]` | Restrict SSH ciphers. Empty list means all secure ciphers from russh defaults are allowed. Example: `["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]`. |
| `allowed_kex` | string[] | `[]` | Restrict SSH key exchange algorithms. Empty list means all secure kex algorithms from russh defaults are allowed. |
| `shutdown_timeout` | u64 | `30` | Graceful shutdown timeout in seconds. Active connections drain during this period before being forcefully closed. |
| `socks5_tls_cert` | string? | `null` | TLS certificate path for the SOCKS5 standalone listener. Both `socks5_tls_cert` and `socks5_tls_key` must be set together. |
| `socks5_tls_key` | string? | `null` | TLS private key path for the SOCKS5 standalone listener. Both must be set together. |
| `dns_cache_ttl` | i64 | `-1` | DNS cache TTL mode. `-1` = follow native DNS TTL (default). `0` = disabled (fresh lookup every time). `N` = custom TTL of N seconds. |
| `dns_cache_max_entries` | u32 | `1000` | Maximum DNS cache entries. Oldest expired entries are evicted first. |
| `connect_retry` | u32 | `0` | Number of retries on outbound TCP connect failure. `0` = disabled. Uses exponential backoff capped at 10 seconds. |
| `connect_retry_delay_ms` | u64 | `1000` | Initial delay in milliseconds for connect retry. Doubles each attempt, capped at 10 seconds. Only used when `connect_retry > 0`. |
| `bookmarks_path` | string? | `null` | Path for persistent bookmarks storage (JSON file). When absent, bookmarks are stored in-memory only and lost on restart. |
| `ssh_keepalive_interval_secs` | u64 | `15` | SSH keepalive interval in seconds. Server sends keepalive requests to detect dead clients and prevent ghost sessions. `0` = disabled. |
| `ssh_keepalive_max` | u32 | `3` | Maximum number of unanswered SSH keepalives before disconnecting the client. |
| `ssh_auth_timeout` | u64 | `120` | Maximum time in seconds allowed for SSH authentication (key exchange + auth). Connections that don't authenticate within this window are rejected. Range: 10-600. |

---

## [shell]

Shell emulator configuration for interactive SSH sessions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `hostname` | string | `"sks5-proxy"` | Hostname shown in the shell prompt (`user@hostname:~$`) and in `uname -n`. |
| `prompt` | string | `"$ "` | Shell prompt suffix string appended after `user@hostname:~`. |
| `colors` | bool | `true` | Enable ANSI color output in the shell (colored prompt, command output). |
| `autocomplete` | bool | `true` | Enable tab-completion for commands and arguments. |

---

## [limits]

Connection and authentication limits.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_connections` | u32 | `1000` | Maximum total concurrent connections across all users. |
| `max_connections_per_user` | u32 | `0` | Maximum concurrent connections per user. `0` = unlimited. |
| `connection_timeout` | u64 | `300` | Connection establishment timeout in seconds (TCP connect to upstream). Must be > 0. |
| `idle_timeout` | u64 | `0` | Idle timeout in seconds. Connections with no data exchanged for this duration are closed. `0` = no timeout (connections stay open indefinitely). |
| `max_auth_attempts` | u32 | `3` | Maximum failed authentication attempts before the SSH connection is closed. |
| `socks5_handshake_timeout` | u64 | `30` | SOCKS5 handshake timeout in seconds (authentication + connect request). Prevents slowloris attacks. Must be between 5 and 120. |
| `idle_warning_secs` | u64 | `0` | Warn users N seconds before idle disconnect by sending a shell message. `0` = no warning. Only effective when `idle_timeout > 0`. |
| `max_bandwidth_mbps` | u64 | `0` | Server-wide bandwidth cap in Mbps. All connections combined cannot exceed this. `0` = unlimited. |
| `max_new_connections_per_second` | u32 | `0` | Server-level maximum new connections per second across all users. `0` = unlimited. |
| `max_new_connections_per_minute` | u32 | `0` | Server-level maximum new connections per minute across all users. `0` = unlimited. |
| `udp_relay_timeout` | u64 | `300` | UDP relay idle timeout in seconds. Range: 30-3600. |
| `max_udp_sessions_per_user` | u32 | `0` | Maximum concurrent UDP relay sessions per user. `0` = unlimited. |

---

## [security]

IP filtering, automatic banning, IP reputation, and TOTP enforcement.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `allowed_source_ips` | IpNet[] | `[]` | IP/CIDR whitelist for source connections. When non-empty, only these IPs can connect (all others rejected). Empty = all source IPs allowed. |
| `ban_enabled` | bool | `true` | Enable automatic IP banning after repeated authentication failures (fail2ban-style). |
| `ban_threshold` | u32 | `5` | Number of failed auth attempts within `ban_window` to trigger a ban. Must be >= 1 when banning is enabled. |
| `ban_window` | u64 | `300` | Time window in seconds in which auth failures are counted toward `ban_threshold`. |
| `ban_duration` | u64 | `900` | How long an IP stays banned in seconds. Auto-unbanned after this duration. |
| `ban_whitelist` | string[] | `[]` | IPs/CIDRs exempt from banning (always allowed, even after failures). |
| `ip_guard_enabled` | bool | `true` | Anti-SSRF guard. Prevents forwarding to private/internal addresses (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7, fe80::/10, ::1, cloud metadata IPs). |
| `totp_required_for` | string[] | `[]` | Protocols requiring TOTP 2FA. Valid values: `"ssh"`, `"socks5"`. Empty = per-user `totp_enabled` still applies. |
| `max_new_connections_per_ip_per_minute` | u32 | `0` | Pre-auth rate limit: max new connections per IP per minute. Applied before authentication. IPs in `ban_whitelist` are exempt. `0` = unlimited. |
| `ip_reputation_enabled` | bool | `false` | Enable IP reputation scoring. Tracks per-IP behavior: auth failure +10, ACL denial +5, rapid connections +3, auth success -5. Scores decay exponentially (halve every hour). |
| `ip_reputation_ban_threshold` | u32 | `100` | Auto-ban threshold for IP reputation score. When exceeded, the IP is automatically banned. `0` = scoring only (no auto-ban). |
| `trusted_user_ca_keys` | string[] | `[]` | Trusted CA public keys for SSH certificate authentication, in OpenSSH authorized_keys format. |
| `argon2_memory_cost` | u32 | `19456` | Argon2id memory cost in KiB. OWASP recommends 19456 (19 MiB) as minimum. |
| `argon2_time_cost` | u32 | `2` | Argon2id time cost (iterations). |
| `argon2_parallelism` | u32 | `1` | Argon2id parallelism (lanes). |
| `rate_limit_cleanup_interval` | u64 | `60` | Interval in seconds for pruning stale rate limiter entries. |
| `rate_limit_max_ips` | usize | `100000` | Maximum IPs tracked by the rate limiter. Oldest entries are evicted when exceeded. |
| `rate_limit_max_users` | usize | `10000` | Maximum usernames tracked by the rate limiter. Oldest entries are evicted when exceeded. |

---

## [logging]

Logging and audit configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | string | `"info"` | Log level. Values: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`. |
| `format` | string | `"pretty"` | Log format. `"pretty"` for human-readable, `"json"` for structured output (for log aggregators). |
| `audit_log_path` | string? | `null` | Separate audit log file path for security events (auth, forwarding, bans). Written in JSON format. When absent, audit events go to the main log only. |
| `audit_max_size_mb` | u64 | `100` | Maximum size per audit log file in MB before rotation. |
| `audit_max_files` | u32 | `5` | Number of rotated audit log files to retain. |
| `connection_flow_logs` | bool | `false` | Enable detailed connection flow logs (per-step timing for each connection). Produces verbose output at debug log level. |
| `log_denied_connections` | bool | `true` | Suppress policy denial log messages (ACL deny, rate limit exceeded, quota exceeded, banned IP, auth timeout, etc.). Metrics and audit events are still recorded. |

---

## [metrics]

Prometheus-compatible metrics endpoint.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the `/metrics` HTTP endpoint for Prometheus scraping. |
| `listen` | string | `"127.0.0.1:9090"` | Listen address for the metrics HTTP server. |
| `max_metric_labels` | u32 | `100` | Maximum distinct user label values in Prometheus metrics. Beyond this cap, new users are aggregated under `"_other"`. Prevents high-cardinality label explosion. |

---

## [api]

HTTP management API server (REST, SSE, WebSocket, dashboard).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the API server. |
| `listen` | string | `"127.0.0.1:9091"` | Listen address for the API HTTP server. |
| `token` | string | `""` | Bearer token for API authentication. **Required when `enabled = true`** (must be non-empty). `GET /api/health` is exempt from auth. `/livez` is always unauthenticated. |

---

## [geoip]

GeoIP-based country filtering. Requires a MaxMind GeoLite2-Country database file.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable GeoIP country filtering. |
| `database_path` | string? | `null` | Path to the GeoLite2-Country.mmdb file. |
| `allowed_countries` | string[] | `[]` | Allow only these countries (ISO 3166-1 alpha-2 codes, e.g., `["FR", "DE", "US"]`). Empty = all countries allowed. Checked before `denied_countries`. |
| `denied_countries` | string[] | `[]` | Block these countries. Empty = none blocked. |
| `fail_closed` | bool | `false` | Behavior when GeoIP lookup fails. `true` = deny access (strict). `false` = allow access (permissive). |

---

## [motd]

Global Message of the Day shown after SSH login. Supports template variables. Can be overridden per group or per user.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable MOTD display. |
| `template` | string? | `null` | Template string with variables. When absent, a built-in default MOTD is used. See [Template Variables](#motd-template-variables). |
| `colors` | bool | `true` | Enable ANSI color codes in MOTD output. |

### MOTD Template Variables

| Variable | Description |
|----------|-------------|
| `{user}` | Username |
| `{auth_method}` | "password", "pubkey", "pubkey+totp" |
| `{source_ip}` | Client IP address |
| `{connections}` | Number of active connections for this user |
| `{acl_policy}` | Effective ACL policy ("allow" or "deny") |
| `{expires_at}` | Account expiration date or "never" |
| `{bandwidth_used}` | Total bandwidth consumed (human-readable) |
| `{bandwidth_limit}` | Bandwidth limit (human-readable) or "unlimited" |
| `{last_login}` | Last login timestamp or "first login" |
| `{uptime}` | Server uptime (human-readable) |
| `{version}` | sks5 version string |
| `{group}` | Group name or "none" |
| `{role}` | "user" or "admin" |
| `{denied}` | Comma-separated ACL deny rules or "none" |
| `{allowed}` | Comma-separated ACL allow rules or "none" |

---

## [acl]

Global Access Control Lists applied to all users. Per-user `[users.acl]` sections inherit these rules by default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_policy` | string | `"allow"` | Default policy when no allow/deny rule matches. Values: `"allow"`, `"deny"`. |
| `allow` | string[] | `[]` | Global allow rules. Checked after deny rules. Format: `"host:port"`, `"cidr:port"`, `"*.pattern:port"`. |
| `deny` | string[] | `[]` | Global deny rules. Always checked first for every user. |

### ACL Rule Format

Rules follow the pattern `target:port`:

| Pattern | Example | Description |
|---------|---------|-------------|
| Exact host + port | `example.com:443` | Specific host and port |
| Wildcard domain | `*.example.com:443` | Any subdomain |
| CIDR subnet | `10.0.0.0/8:80` | IP range |
| Port range | `host:80-443` | Port range (inclusive) |
| All ports | `host:*` | Any port on host |
| All destinations | `*:*` | Everything |
| IPv6 | `[2606:2800:220:1::]:443` | IPv6 address in brackets |

---

## [upstream_proxy]

Route all outbound proxy traffic through an upstream SOCKS5 proxy. Absent by default (direct connections).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | _(required)_ | Upstream SOCKS5 proxy URL (e.g., `"socks5://proxy.internal:1080"`). |

---

## [connection_pool]

TCP connection pooling for outbound proxy connections. Reuses idle connections to reduce latency.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable connection pooling. |
| `max_idle_per_host` | u32 | `10` | Maximum idle connections kept per host:port. |
| `idle_timeout_secs` | u64 | `60` | Seconds before an idle pooled connection is closed and evicted. |

---

## [[users]]

User definitions. **At least one user is required.** Each user needs at least one of `password_hash` or `authorized_keys`. Usernames must be unique.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `username` | string | _(required)_ | Unique username. |
| `password_hash` | string? | `null` | Argon2id password hash. Generate with `sks5 hash-password`. |
| `authorized_keys` | string[] | `[]` | SSH public keys for key-based authentication, in OpenSSH format. |
| `allow_shell` | bool | `true` | Allow interactive shell access. |
| `group` | string? | `null` | Group membership. References a `[[groups]]` entry by name. User fields override group defaults. |
| `role` | string | `"user"` | User role: `"user"` or `"admin"`. Admins see extended info in shell commands like `show status`. |
| `max_new_connections_per_minute` | u32 | `0` | Rate limit: max new connections per minute for this user. `0` = unlimited. |
| `max_bandwidth_kbps` | u64 | `0` | Bandwidth cap in Kbps per individual connection. `0` = unlimited. |
| `max_aggregate_bandwidth_kbps` | u64 | `0` | Total bandwidth cap across all concurrent connections for this user (Kbps). `0` = unlimited. |
| `max_connections` | u32? | `null` | Maximum concurrent connections for this user. Overrides group/global `max_connections_per_user`. `0` = unlimited. `null` = inherit. |
| `source_ips` | IpNet[] | `[]` | Restrict source IPs. Only these IPs/CIDRs can authenticate as this user. Empty = any source IP. |
| `expires_at` | string? | `null` | Account expiration in ISO 8601 format (e.g., `"2026-12-31T23:59:59Z"`). After this date, authentication is rejected. |
| `upstream_proxy` | string? | `null` | Per-user upstream proxy URL. Overrides global `[upstream_proxy]`. |
| `totp_enabled` | bool | `false` | Enable TOTP 2FA. Requires `totp_secret` to be set. User appends 6-digit TOTP code to password. |
| `totp_secret` | string? | `null` | Base32-encoded TOTP secret. Generate with `sks5 generate-totp --username <name>`. |
| `auth_methods` | string[]? | `null` | Auth method chain. E.g., `["pubkey", "password"]` means both required in order. `null` = any configured method accepted. |
| `idle_warning_secs` | u64? | `null` | Seconds before idle disconnect to warn user. Overrides group/global `idle_warning_secs`. `null` = inherit. |
| `colors` | bool? | `null` | ANSI color override for shell output. `null` = inherit from group or global `[shell].colors`. |
| `connect_retry` | u32? | `null` | Smart retry override (outbound connection retries). `null` = inherit from server. |
| `connect_retry_delay_ms` | u64? | `null` | Smart retry delay override in milliseconds. `null` = inherit from server. |
| `aliases` | map<string, string> | `{}` | Shell aliases. Keys are alias names, values are expanded commands. Example: `{db = "test prod-db:5432"}`. |

---

## [users.acl]

Per-user Access Control List. Merged with global `[acl]` by default.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_policy` | string? | `null` | Override the global ACL default policy for this user. Values: `"allow"`, `"deny"`. `null` = inherit from global `[acl].default_policy`. |
| `allow` | string[] | `[]` | Allow rules added to global rules (when `inherit = true`). Same format as global ACL rules. |
| `deny` | string[] | `[]` | Deny rules added to global rules (when `inherit = true`). |
| `inherit` | bool | `true` | Inherit global `[acl]` rules. `true` = merge user rules with global. `false` = ignore global ACL entirely, use only user's rules. |

---

## [users.shell_permissions]

Per-user shell command permissions. Overrides group/global defaults. All permissions default to `true` when not specified.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `show_connections` | bool | `true` | Allow `show connections` command. |
| `show_bandwidth` | bool | `true` | Allow `show bandwidth` command. |
| `show_acl` | bool | `true` | Allow `show acl` command. |
| `show_status` | bool | `true` | Allow `show status` command. |
| `show_history` | bool | `true` | Allow `show history` command. |
| `show_fingerprint` | bool | `true` | Allow `show fingerprint` command. |
| `test_command` | bool | `true` | Allow `test host:port` command. |
| `ping_command` | bool | `true` | Allow `ping host` command. |
| `resolve_command` | bool | `true` | Allow `resolve hostname` command. |
| `bookmark_command` | bool | `true` | Allow `bookmark add/list/del` commands. |
| `alias_command` | bool | `true` | Allow `alias add/list/del` commands. |
| `show_quota` | bool | `true` | Controls `show quota` command and quota-related MOTD lines. |
| `show_role` | bool | `true` | Controls `{role}` in MOTD and role line in `show status`. |
| `show_group` | bool | `true` | Controls `{group}` in MOTD and group line in `show status`. |
| `show_expires` | bool | `true` | Controls `{expires_at}` in MOTD and expires line in `show status`. |
| `show_source_ip` | bool | `true` | Controls `{source_ip}` in MOTD and source IP line in `show status`. |
| `show_auth_method` | bool | `true` | Controls `{auth_method}` in MOTD and auth method line in `show status`. |
| `show_uptime` | bool | `true` | Controls `{uptime}` in MOTD and uptime line in `show status`. |

---

## [users.motd]

Per-user MOTD override. Takes precedence over group and global `[motd]`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable MOTD display for this user. |
| `template` | string? | `null` | Custom MOTD template. Supports the same variables as global `[motd]`. |
| `colors` | bool | `true` | Enable ANSI color codes in MOTD output. |

---

## [users.quotas]

Per-user usage quotas. All values default to `0` (unlimited). User quotas override group quotas.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `daily_bandwidth_bytes` | u64 | `0` | Maximum bytes per day. Resets at midnight UTC. `0` = unlimited. |
| `daily_connection_limit` | u32 | `0` | Maximum connections per day. `0` = unlimited. |
| `monthly_bandwidth_bytes` | u64 | `0` | Maximum bytes per month. Resets on the 1st of each month. `0` = unlimited. |
| `monthly_connection_limit` | u32 | `0` | Maximum connections per month. `0` = unlimited. |
| `bandwidth_per_hour_bytes` | u64 | `0` | Maximum bytes per hour (rolling window). `0` = unlimited. |
| `total_bandwidth_bytes` | u64 | `0` | Maximum total bytes ever. Never auto-resets. `0` = unlimited. Useful for metered/prepaid accounts. |

---

## [users.time_access]

Per-user time-based access restrictions.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `access_hours` | string? | `null` | Allowed hours in `"HH:MM-HH:MM"` format (e.g., `"08:00-18:00"`). `null` = 24-hour access. |
| `access_days` | string[] | `[]` | Allowed days of the week. Values: `"mon"`, `"tue"`, `"wed"`, `"thu"`, `"fri"`, `"sat"`, `"sun"`. Empty = all days allowed. |

---

## [users.rate_limits]

Per-user multi-window rate limits for new connections. Overrides group and server-level defaults.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connections_per_second` | u32 | `0` | Maximum new connections per second. `0` = unlimited. |
| `connections_per_minute` | u32 | `0` | Maximum new connections per minute. `0` = unlimited. |
| `connections_per_hour` | u32 | `0` | Maximum new connections per hour. `0` = unlimited. |

---

## [[groups]]

User groups for shared configuration inheritance. Users reference groups via the `group` field. Inheritance order: user > group > global defaults. All group fields (except `name`) are optional and serve as defaults for members.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | _(required)_ | Group name. Referenced by `[[users]].group`. |
| `max_connections_per_user` | u32? | `null` | Max concurrent connections per user in this group. `null` = inherit from global. |
| `max_bandwidth_kbps` | u64? | `null` | Per-connection bandwidth cap (Kbps). `null` = inherit. |
| `max_aggregate_bandwidth_kbps` | u64? | `null` | Aggregate bandwidth cap for group members (Kbps). `null` = inherit. |
| `max_new_connections_per_minute` | u32? | `null` | Rate limit: max new connections per minute. `null` = inherit. |
| `allow_shell` | bool? | `null` | Allow interactive shell. `null` = inherit (default `true`). |
| `role` | string? | `null` | Default role for group members: `"user"` or `"admin"`. `null` = inherit (default `"user"`). |
| `colors` | bool? | `null` | ANSI colors in shell. `null` = inherit. |
| `connect_retry` | u32? | `null` | Connect retry count. `null` = inherit from server. |
| `connect_retry_delay_ms` | u64? | `null` | Connect retry initial delay (ms). `null` = inherit. |
| `idle_warning_secs` | u64? | `null` | Idle warning seconds. `null` = inherit. |
| `auth_methods` | string[]? | `null` | Auth method chain. `null` = inherit. |

---

## [groups.acl]

Group-level ACL. Same structure as `[users.acl]`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_policy` | string? | `null` | Override global ACL default policy. `null` = inherit. |
| `allow` | string[] | `[]` | Allow rules. |
| `deny` | string[] | `[]` | Deny rules. |
| `inherit` | bool | `true` | Inherit global `[acl]` rules. |

---

## [groups.shell_permissions]

Group-level shell permissions. Same structure as `[users.shell_permissions]`. All default to `true`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `show_connections` | bool | `true` | Allow `show connections`. |
| `show_bandwidth` | bool | `true` | Allow `show bandwidth`. |
| `show_acl` | bool | `true` | Allow `show acl`. |
| `show_status` | bool | `true` | Allow `show status`. |
| `show_history` | bool | `true` | Allow `show history`. |
| `show_fingerprint` | bool | `true` | Allow `show fingerprint`. |
| `test_command` | bool | `true` | Allow `test host:port`. |
| `ping_command` | bool | `true` | Allow `ping host`. |
| `resolve_command` | bool | `true` | Allow `resolve hostname`. |
| `bookmark_command` | bool | `true` | Allow `bookmark add/list/del`. |
| `alias_command` | bool | `true` | Allow `alias add/list/del`. |
| `show_quota` | bool | `true` | Controls `show quota` and quota MOTD lines. |
| `show_role` | bool | `true` | Controls `{role}` in MOTD and `show status`. |
| `show_group` | bool | `true` | Controls `{group}` in MOTD and `show status`. |
| `show_expires` | bool | `true` | Controls `{expires_at}` in MOTD and `show status`. |
| `show_source_ip` | bool | `true` | Controls `{source_ip}` in MOTD and `show status`. |
| `show_auth_method` | bool | `true` | Controls `{auth_method}` in MOTD and `show status`. |
| `show_uptime` | bool | `true` | Controls `{uptime}` in MOTD and `show status`. |

---

## [groups.motd]

Group-level MOTD override. Takes precedence over global `[motd]` but is overridden by `[users.motd]`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable MOTD for group members. |
| `template` | string? | `null` | Custom MOTD template. |
| `colors` | bool | `true` | Enable ANSI colors in MOTD. |

---

## [groups.quotas]

Group-level quotas. Same structure as `[users.quotas]`. Overridden by per-user quotas.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `daily_bandwidth_bytes` | u64 | `0` | Max bytes per day. `0` = unlimited. |
| `daily_connection_limit` | u32 | `0` | Max connections per day. `0` = unlimited. |
| `monthly_bandwidth_bytes` | u64 | `0` | Max bytes per month. `0` = unlimited. |
| `monthly_connection_limit` | u32 | `0` | Max connections per month. `0` = unlimited. |
| `bandwidth_per_hour_bytes` | u64 | `0` | Max bytes per hour (rolling). `0` = unlimited. |
| `total_bandwidth_bytes` | u64 | `0` | Max total bytes ever. Never resets. `0` = unlimited. |

---

## [groups.time_access]

Group-level time-based access restrictions. Same structure as `[users.time_access]`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `access_hours` | string? | `null` | Allowed hours (`"HH:MM-HH:MM"`). `null` = 24h access. |
| `access_days` | string[] | `[]` | Allowed days. Empty = all days. |

---

## [groups.rate_limits]

Group-level multi-window rate limits. Same structure as `[users.rate_limits]`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `connections_per_second` | u32 | `0` | Max new connections per second. `0` = unlimited. |
| `connections_per_minute` | u32 | `0` | Max new connections per minute. `0` = unlimited. |
| `connections_per_hour` | u32 | `0` | Max new connections per hour. `0` = unlimited. |

---

## [[webhooks]]

HTTP webhooks triggered by server events. Repeatable section (define multiple webhooks).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `url` | string | _(required)_ | Webhook delivery URL. Must be a valid HTTP/HTTPS URL. |
| `events` | string[] | `[]` | Event types to subscribe to. Empty = all events. Valid values: `"auth_success"`, `"auth_failure"`, `"connection_open"`, `"connection_close"`, `"proxy_complete"`, `"ban"`, `"unban"`, `"config_reload"`, `"maintenance_start"`, `"maintenance_end"`, `"rate_limited"`, `"quota_exceeded"`, `"alert_triggered"`. |
| `format` | string | `"generic"` | Payload format. Values: `"generic"` (raw JSON), `"slack"` (Block Kit), `"discord"` (embed), `"custom"` (template). |
| `template` | string? | `null` | Custom template string. **Required when `format = "custom"`**. Placeholders: `{event_type}`, `{timestamp}`, `{username}`, `{source_ip}`, `{target_host}`, `{data_json}`, `{summary}`. Values are JSON-escaped. |
| `secret` | string? | `null` | HMAC-SHA256 secret for `X-Signature-256` header verification. When absent, no signature is included. HMAC is computed on the final formatted body. |
| `allow_private_ips` | bool | `false` | Allow delivery to private/internal IPs (RFC 1918, loopback). Set `true` for local webhook receivers. |
| `max_retries` | u32 | `3` | Maximum retry attempts on delivery failure. `0` = no retries. |
| `retry_delay_ms` | u64 | `1000` | Initial retry delay in milliseconds. Doubled each attempt (exponential backoff). |
| `max_retry_delay_ms` | u64 | `30000` | Maximum retry delay in milliseconds (cap for exponential backoff). |

---

## [alerting]

Alerting engine configuration.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the alerting engine. |
| `rules` | AlertRule[] | `[]` | List of alert rules. See `[[alerting.rules]]`. |

---

## [[alerting.rules]]

Individual alert rules. Trigger when a condition exceeds a threshold within a time window.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | _(required)_ | Rule name (for logging and identification). |
| `condition` | string | _(required)_ | Condition type. Values: `"bandwidth_exceeded"`, `"connections_exceeded"`, `"auth_failures"`, `"monthly_bandwidth_exceeded"`, `"hourly_bandwidth_exceeded"`. |
| `threshold` | u64 | _(required)_ | Threshold value. For bandwidth: bytes. For connections/auth failures: count. |
| `window_secs` | u64 | `3600` | Evaluation window in seconds. |
| `users` | string[] | `[]` | Users to apply the rule to. Empty = all users. |
| `webhook_url` | string? | `null` | Webhook URL to notify when the rule fires. Uses the webhook delivery infrastructure. When absent, the alert is logged but no webhook is sent. |

---

## [[maintenance_windows]]

Scheduled maintenance windows. During maintenance, new connections are rejected with a message. Repeatable section.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `schedule` | string | _(required)_ | Schedule expression. Format: `"Sun 02:00-04:00"` (day-specific) or `"daily 03:00-04:00"` (every day). |
| `message` | string | `"Server is under scheduled maintenance. Please try again later."` | Message shown to users who attempt to connect during maintenance. |
| `disconnect_existing` | bool | `false` | Gracefully disconnect existing connections when maintenance starts. |

---

## Configuration Inheritance

Many settings follow a three-level inheritance model:

```
user setting > group setting > global default
```

When a user-level value is set, it takes precedence. When absent (`null`/`None`), the group-level value is used. When the group-level value is also absent, the global default applies.

This applies to:
- `allow_shell`
- `max_bandwidth_kbps`, `max_aggregate_bandwidth_kbps`, `max_connections_per_user`
- `role`, `colors`, `connect_retry`, `connect_retry_delay_ms`, `idle_warning_secs`
- `auth_methods`
- `shell_permissions` (entire block)
- `motd` (entire block)
- `quotas` (entire block)
- `time_access` (entire block)
- `rate_limits` (entire block)
- `acl` (with `inherit` flag controlling global merge behavior)

---

## Environment Variable Reference

When running without a config file, the following environment variables are recognized. Boolean values accept `true`/`1`/`yes` (case-insensitive). CSV values are comma-separated.

### Server

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_SSH_LISTEN` | string | _(required)_ | `server.ssh_listen` |
| `SKS5_SOCKS5_LISTEN` | string | _(none)_ | `server.socks5_listen` |
| `SKS5_HOST_KEY_PATH` | string | `"host_key"` | `server.host_key_path` |
| `SKS5_SERVER_ID` | string | auto | `server.server_id` |
| `SKS5_BANNER` | string | `"Welcome to sks5"` | `server.banner` |
| `SKS5_MOTD_PATH` | string | _(none)_ | `server.motd_path` |
| `SKS5_ALLOWED_CIPHERS` | CSV | `""` | `server.allowed_ciphers` |
| `SKS5_ALLOWED_KEX` | CSV | `""` | `server.allowed_kex` |
| `SKS5_SHUTDOWN_TIMEOUT` | u64 | `30` | `server.shutdown_timeout` |
| `SKS5_SOCKS5_TLS_CERT` | string | _(none)_ | `server.socks5_tls_cert` |
| `SKS5_SOCKS5_TLS_KEY` | string | _(none)_ | `server.socks5_tls_key` |
| `SKS5_DNS_CACHE_TTL` | i64 | `-1` | `server.dns_cache_ttl` |
| `SKS5_DNS_CACHE_MAX_ENTRIES` | u32 | `1000` | `server.dns_cache_max_entries` |
| `SKS5_CONNECT_RETRY` | u32 | `0` | `server.connect_retry` |
| `SKS5_CONNECT_RETRY_DELAY_MS` | u64 | `1000` | `server.connect_retry_delay_ms` |
| `SKS5_BOOKMARKS_PATH` | string | _(none)_ | `server.bookmarks_path` |
| `SKS5_SSH_KEEPALIVE_INTERVAL` | u64 | `15` | `server.ssh_keepalive_interval_secs` |
| `SKS5_SSH_KEEPALIVE_MAX` | u32 | `3` | `server.ssh_keepalive_max` |
| `SKS5_SSH_AUTH_TIMEOUT` | u64 | `120` | `server.ssh_auth_timeout` |

### Shell

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_SHELL_HOSTNAME` | string | `"sks5-proxy"` | `shell.hostname` |
| `SKS5_SHELL_PROMPT` | string | `"$ "` | `shell.prompt` |
| `SKS5_SHELL_COLORS` | bool | `true` | `shell.colors` |
| `SKS5_SHELL_AUTOCOMPLETE` | bool | `true` | `shell.autocomplete` |

### Limits

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_MAX_CONNECTIONS` | u32 | `1000` | `limits.max_connections` |
| `SKS5_MAX_CONNECTIONS_PER_USER` | u32 | `0` | `limits.max_connections_per_user` |
| `SKS5_CONNECTION_TIMEOUT` | u64 | `300` | `limits.connection_timeout` |
| `SKS5_IDLE_TIMEOUT` | u64 | `0` | `limits.idle_timeout` |
| `SKS5_MAX_AUTH_ATTEMPTS` | u32 | `3` | `limits.max_auth_attempts` |
| `SKS5_SOCKS5_HANDSHAKE_TIMEOUT` | u64 | `30` | `limits.socks5_handshake_timeout` |
| `SKS5_IDLE_WARNING_SECS` | u64 | `0` | `limits.idle_warning_secs` |
| `SKS5_MAX_BANDWIDTH_MBPS` | u64 | `0` | `limits.max_bandwidth_mbps` |
| `SKS5_MAX_NEW_CONNECTIONS_PER_SECOND` | u32 | `0` | `limits.max_new_connections_per_second` |
| `SKS5_MAX_NEW_CONNECTIONS_PER_MINUTE_SERVER` | u32 | `0` | `limits.max_new_connections_per_minute` |
| `SKS5_UDP_RELAY_TIMEOUT` | u64 | `300` | `limits.udp_relay_timeout` |
| `SKS5_MAX_UDP_SESSIONS_PER_USER` | u32 | `0` | `limits.max_udp_sessions_per_user` |

### Security

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_ALLOWED_SOURCE_IPS` | CSV (CIDR) | `""` | `security.allowed_source_ips` |
| `SKS5_BAN_ENABLED` | bool | `true` | `security.ban_enabled` |
| `SKS5_BAN_THRESHOLD` | u32 | `5` | `security.ban_threshold` |
| `SKS5_BAN_WINDOW` | u64 | `300` | `security.ban_window` |
| `SKS5_BAN_DURATION` | u64 | `900` | `security.ban_duration` |
| `SKS5_BAN_WHITELIST` | CSV | `""` | `security.ban_whitelist` |
| `SKS5_IP_GUARD_ENABLED` | bool | `true` | `security.ip_guard_enabled` |
| `SKS5_TOTP_REQUIRED_FOR` | CSV | `""` | `security.totp_required_for` |
| `SKS5_MAX_NEW_CONNECTIONS_PER_IP_PER_MINUTE` | u32 | `0` | `security.max_new_connections_per_ip_per_minute` |
| `SKS5_IP_REPUTATION_ENABLED` | bool | `false` | `security.ip_reputation_enabled` |
| `SKS5_IP_REPUTATION_BAN_THRESHOLD` | u32 | `100` | `security.ip_reputation_ban_threshold` |
| `SKS5_TRUSTED_USER_CA_KEYS` | CSV | `""` | `security.trusted_user_ca_keys` |
| `SKS5_ARGON2_MEMORY_COST` | u32 | `19456` | `security.argon2_memory_cost` |
| `SKS5_ARGON2_TIME_COST` | u32 | `2` | `security.argon2_time_cost` |
| `SKS5_ARGON2_PARALLELISM` | u32 | `1` | `security.argon2_parallelism` |
| `SKS5_RATE_LIMIT_CLEANUP_INTERVAL` | u64 | `60` | `security.rate_limit_cleanup_interval` |
| `SKS5_RATE_LIMIT_MAX_IPS` | usize | `100000` | `security.rate_limit_max_ips` |
| `SKS5_RATE_LIMIT_MAX_USERS` | usize | `10000` | `security.rate_limit_max_users` |

### Logging

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_LOG_LEVEL` | string | `"info"` | `logging.level` |
| `SKS5_LOG_FORMAT` | string | `"pretty"` | `logging.format` |
| `SKS5_AUDIT_LOG_PATH` | string | _(none)_ | `logging.audit_log_path` |
| `SKS5_AUDIT_MAX_SIZE_MB` | u64 | `100` | `logging.audit_max_size_mb` |
| `SKS5_AUDIT_MAX_FILES` | u32 | `5` | `logging.audit_max_files` |
| `SKS5_CONNECTION_FLOW_LOGS` | bool | `false` | `logging.connection_flow_logs` |
| `SKS5_LOG_DENIED_CONNECTIONS` | bool | `true` | `logging.log_denied_connections` |

### Metrics and API

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_METRICS_ENABLED` | bool | `false` | `metrics.enabled` |
| `SKS5_METRICS_LISTEN` | string | `"127.0.0.1:9090"` | `metrics.listen` |
| `SKS5_MAX_METRIC_LABELS` | u32 | `100` | `metrics.max_metric_labels` |
| `SKS5_API_ENABLED` | bool | `false` | `api.enabled` |
| `SKS5_API_LISTEN` | string | `"127.0.0.1:9091"` | `api.listen` |
| `SKS5_API_TOKEN` | string | `""` | `api.token` |
| `SKS5_API_TOKEN_FILE` | string | _(none)_ | `api.token` (read from file) |

### GeoIP

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_GEOIP_ENABLED` | bool | `false` | `geoip.enabled` |
| `SKS5_GEOIP_DATABASE_PATH` | string | _(none)_ | `geoip.database_path` |
| `SKS5_GEOIP_ALLOWED_COUNTRIES` | CSV | `""` | `geoip.allowed_countries` |
| `SKS5_GEOIP_DENIED_COUNTRIES` | CSV | `""` | `geoip.denied_countries` |
| `SKS5_GEOIP_FAIL_CLOSED` | bool | `false` | `geoip.fail_closed` |

### Global ACL

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_GLOBAL_ACL_DEFAULT_POLICY` | string | `"allow"` | `acl.default_policy` |
| `SKS5_GLOBAL_ACL_ALLOW` | CSV | `""` | `acl.allow` |
| `SKS5_GLOBAL_ACL_DENY` | CSV | `""` | `acl.deny` |

### Upstream Proxy

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_UPSTREAM_PROXY_URL` | string | _(none)_ | `upstream_proxy.url` |

### Single-User Mode

| Variable | Type | Default | Maps to |
|----------|------|---------|---------|
| `SKS5_USERNAME` | string | `"user"` | `users[0].username` |
| `SKS5_PASSWORD_HASH` | string | _(none)_ | `users[0].password_hash` |
| `SKS5_PASSWORD_HASH_FILE` | string | _(none)_ | `users[0].password_hash` (read from file) |
| `SKS5_AUTHORIZED_KEYS` | CSV | `""` | `users[0].authorized_keys` |
| `SKS5_ALLOW_SHELL` | bool | `true` | `users[0].allow_shell` |
| `SKS5_MAX_NEW_CONNECTIONS_PER_MINUTE` | u32 | `0` | `users[0].max_new_connections_per_minute` |
| `SKS5_MAX_BANDWIDTH_KBPS` | u64 | `0` | `users[0].max_bandwidth_kbps` |
| `SKS5_MAX_AGGREGATE_BANDWIDTH_KBPS` | u64 | `0` | `users[0].max_aggregate_bandwidth_kbps` |
| `SKS5_SOURCE_IPS` | CSV (CIDR) | `""` | `users[0].source_ips` |
| `SKS5_EXPIRES_AT` | string | _(none)_ | `users[0].expires_at` |
| `SKS5_TOTP_ENABLED` | bool | `false` | `users[0].totp_enabled` |
| `SKS5_TOTP_SECRET` | string | _(none)_ | `users[0].totp_secret` |
| `SKS5_TOTP_SECRET_FILE` | string | _(none)_ | `users[0].totp_secret` (read from file) |
| `SKS5_ACL_DEFAULT_POLICY` | string | _(none)_ | `users[0].acl.default_policy` |
| `SKS5_ACL_ALLOW` | CSV | `""` | `users[0].acl.allow` |
| `SKS5_ACL_DENY` | CSV | `""` | `users[0].acl.deny` |
| `SKS5_ACL_INHERIT` | bool | `true` | `users[0].acl.inherit` |
| `SKS5_GROUP` | string | _(none)_ | `users[0].group` |
| `SKS5_MAX_CONNECTIONS_USER` | u32 | _(none)_ | `users[0].max_connections` |
| `SKS5_RATE_LIMIT_PER_SECOND` | u32 | `0` | `users[0].rate_limits.connections_per_second` |
| `SKS5_RATE_LIMIT_PER_MINUTE` | u32 | `0` | `users[0].rate_limits.connections_per_minute` |
| `SKS5_RATE_LIMIT_PER_HOUR` | u32 | `0` | `users[0].rate_limits.connections_per_hour` |

### Multi-User Indexed Mode

Replace `<N>` with 0, 1, 2, etc. Stops at the first missing index.

| Variable Pattern | Type | Maps to |
|-----------------|------|---------|
| `SKS5_USER_<N>_USERNAME` | string | `users[N].username` |
| `SKS5_USER_<N>_PASSWORD_HASH` | string | `users[N].password_hash` |
| `SKS5_USER_<N>_PASSWORD_HASH_FILE` | string | `users[N].password_hash` (from file) |
| `SKS5_USER_<N>_AUTHORIZED_KEYS` | CSV | `users[N].authorized_keys` |
| `SKS5_USER_<N>_ALLOW_SHELL` | bool | `users[N].allow_shell` |
| `SKS5_USER_<N>_MAX_NEW_CONNECTIONS_PER_MINUTE` | u32 | `users[N].max_new_connections_per_minute` |
| `SKS5_USER_<N>_MAX_BANDWIDTH_KBPS` | u64 | `users[N].max_bandwidth_kbps` |
| `SKS5_USER_<N>_MAX_AGGREGATE_BANDWIDTH_KBPS` | u64 | `users[N].max_aggregate_bandwidth_kbps` |
| `SKS5_USER_<N>_SOURCE_IPS` | CSV (CIDR) | `users[N].source_ips` |
| `SKS5_USER_<N>_EXPIRES_AT` | string | `users[N].expires_at` |
| `SKS5_USER_<N>_UPSTREAM_PROXY` | string | `users[N].upstream_proxy` |
| `SKS5_USER_<N>_TOTP_ENABLED` | bool | `users[N].totp_enabled` |
| `SKS5_USER_<N>_TOTP_SECRET` | string | `users[N].totp_secret` |
| `SKS5_USER_<N>_TOTP_SECRET_FILE` | string | `users[N].totp_secret` (from file) |
| `SKS5_USER_<N>_ACL_DEFAULT_POLICY` | string | `users[N].acl.default_policy` |
| `SKS5_USER_<N>_ACL_ALLOW` | CSV | `users[N].acl.allow` |
| `SKS5_USER_<N>_ACL_DENY` | CSV | `users[N].acl.deny` |
| `SKS5_USER_<N>_ACL_INHERIT` | bool | `users[N].acl.inherit` |
| `SKS5_USER_<N>_GROUP` | string | `users[N].group` |
| `SKS5_USER_<N>_MAX_CONNECTIONS` | u32 | `users[N].max_connections` |
| `SKS5_USER_<N>_RATE_LIMIT_PER_SECOND` | u32 | `users[N].rate_limits.connections_per_second` |
| `SKS5_USER_<N>_RATE_LIMIT_PER_MINUTE` | u32 | `users[N].rate_limits.connections_per_minute` |
| `SKS5_USER_<N>_RATE_LIMIT_PER_HOUR` | u32 | `users[N].rate_limits.connections_per_hour` |
