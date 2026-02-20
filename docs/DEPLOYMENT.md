# sks5 Deployment Guide

## Table of Contents

- [Production Checklist](#production-checklist)
- [Sizing](#sizing)
- [Docker/Podman Deployment](#dockerpodman-deployment)
  - [Building the Image](#building-the-image)
  - [Docker Compose](#docker-compose)
  - [Environment Variable Configuration](#environment-variable-configuration)
  - [Docker Secrets](#docker-secrets)
  - [Health Checks](#health-checks)
  - [Volume Mounts](#volume-mounts)
- [Systemd Deployment](#systemd-deployment)
  - [Installing the Binary](#installing-the-binary)
  - [Creating the Service User](#creating-the-service-user)
  - [Systemd Unit File](#systemd-unit-file)
  - [Enabling and Starting](#enabling-and-starting)
  - [Viewing Logs](#viewing-logs)
  - [Log Rotation](#log-rotation)
- [Monitoring Setup](#monitoring-setup)
  - [Prometheus Scrape Config](#prometheus-scrape-config)
  - [Key Metrics](#key-metrics)
  - [Grafana Dashboard Suggestions](#grafana-dashboard-suggestions)
  - [Alerting with Webhooks](#alerting-with-webhooks)
- [Backup and Restore](#backup-and-restore)
  - [CLI Backup](#cli-backup)
  - [CLI Restore](#cli-restore)
  - [Automating with Cron](#automating-with-cron)
  - [What Gets Backed Up](#what-gets-backed-up)
- [High Availability Notes](#high-availability-notes)

---

## Production Checklist

Before deploying sks5 to production, review the following checklist:

- [ ] **Strong password hashes**: Generate all password hashes with `sks5 hash-password`. Never use weak or example hashes.
- [ ] **Strong API token**: Set a long, random API token (at least 32 characters). Use `openssl rand -hex 32` to generate one.
- [ ] **TLS for SOCKS5**: If the standalone SOCKS5 listener is exposed to the internet, enable TLS:
  ```toml
  [server]
  socks5_tls_cert = "/etc/sks5/tls/socks5.crt"
  socks5_tls_key = "/etc/sks5/tls/socks5.key"
  ```
- [ ] **ACL deny rules**: Block access to private IP ranges and cloud metadata endpoints:
  ```toml
  [acl]
  deny = [
      "169.254.169.254:*",
      "10.0.0.0/8:*",
      "172.16.0.0/12:*",
      "192.168.0.0/16:*",
  ]
  ```
- [ ] **IP Guard enabled**: Keep `ip_guard_enabled = true` (default) to prevent SSRF attacks.
- [ ] **Audit logging**: Enable and configure the audit log for security event tracking:
  ```toml
  [logging]
  audit_log_path = "/var/log/sks5/audit.json"
  audit_max_size_mb = 100
  audit_max_files = 5
  ```
- [ ] **Auto-banning**: Enable banning with appropriate thresholds:
  ```toml
  [security]
  ban_enabled = true
  ban_threshold = 5
  ban_window = 300
  ban_duration = 900
  ```
- [ ] **Connection limits**: Set reasonable limits:
  ```toml
  [limits]
  max_connections = 1000
  max_connections_per_user = 50
  connection_timeout = 300
  idle_timeout = 3600
  max_auth_attempts = 3
  ```
- [ ] **Rate limiting**: Protect against connection flooding:
  ```toml
  [limits]
  max_new_connections_per_second = 50
  max_new_connections_per_minute = 500

  [security]
  max_new_connections_per_ip_per_minute = 30
  ```
- [ ] **Log rotation**: Either use the built-in audit log rotation or configure external logrotate.
- [ ] **File descriptors**: Set `LimitNOFILE` appropriately in systemd or `ulimit -n` in Docker (at least 2x max_connections).
- [ ] **Config validation**: Run `sks5 check-config` before deploying any config change.
- [ ] **Host key persistence**: Ensure `host_key_path` points to a persistent location so the SSH host key survives container restarts.

---

## Sizing

### Memory

- **Base footprint**: approximately 1 MB RSS for the server process with no connections
- **Per active connection**: approximately 2 KB of overhead for connection tracking, ACL state, and relay buffers
- **Shell sessions**: approximately 5 KB additional per interactive SSH session (virtual filesystem, command history)
- **Metrics/API**: approximately 2 MB additional when Prometheus metrics and the API server are enabled
- **Example**: 1000 concurrent connections requires approximately 3 MB total

### CPU

- **Relay mode**: Minimal CPU usage. Bidirectional data relay is primarily I/O-bound (async tokio).
- **Argon2id hashing**: CPU-intensive. Each authentication attempt uses significant CPU for password verification. Consider this when setting `max_new_connections_per_second` on CPU-constrained systems.
- **Metrics encoding**: Brief CPU spikes during Prometheus scrapes, proportional to the number of tracked users.

### Bandwidth

- Depends entirely on use case. sks5 adds negligible overhead to the forwarded data stream.
- Per-user and server-wide bandwidth caps should be set according to your network capacity.

### File Descriptors

Each active proxy connection uses 2 file descriptors (client socket + upstream socket). SSH sessions use 1 additional descriptor.

**Recommended `LimitNOFILE` formula:**

```
LimitNOFILE = (max_connections * 3) + 256 (for listeners, metrics, API, internal FDs)
```

For 1000 connections: `LimitNOFILE = 3256` (round up to 4096 or 65535 for safety).

The provided systemd unit sets `LimitNOFILE=65535`.

---

## Docker/Podman Deployment

sks5 ships with a `Containerfile` (aliased as `Dockerfile`) compatible with both Podman and Docker. It uses a multi-stage build with a minimal Debian bookworm-slim runtime image.

### Building the Image

```bash
# Podman (preferred)
podman build -t sks5:latest .

# Docker
docker build -t sks5:latest .

# Multi-architecture (amd64 + arm64) using cross-compilation
./scripts/build-multiarch-cross.sh

# Multi-architecture using QEMU emulation
./scripts/build-multiarch-qemu.sh
```

The image:
- Runs as a non-root `sks5` user
- Exposes ports 2222 (SSH), 1080 (SOCKS5), 9090 (metrics), 9091 (API)
- Uses `/etc/sks5` as the working directory and volume mount point
- Includes a built-in health check via `sks5 health-check`

### Docker Compose

The provided `docker-compose.yml` supports three profiles:

**Mode 1: Config file (default)**

```bash
docker compose up -d
# or
podman-compose up -d
```

This mounts `config.example.toml` as the config file. Replace it with your production config:

```yaml
volumes:
  - ./config.toml:/etc/sks5/config.toml:ro
  - sks5-hostkey:/etc/sks5/keys
```

**Mode 2: Environment variables with Docker secrets**

```bash
docker compose --profile env up -d
```

Uses indexed `SKS5_USER_<N>_*` environment variables with secrets for sensitive values.

**Mode 3: TLS SOCKS5**

```bash
docker compose --profile tls up -d
```

Enables TLS on the SOCKS5 standalone listener with mounted certificate files.

### Environment Variable Configuration

When running without a config file, set all configuration via environment variables:

```bash
podman run -d \
  --name sks5 \
  -p 2222:2222 \
  -p 1080:1080 \
  -e SKS5_SSH_LISTEN=0.0.0.0:2222 \
  -e SKS5_SOCKSKS5_LISTEN=0.0.0.0:1080 \
  -e SKS5_USER_0_USERNAME=alice \
  -e SKS5_USER_0_PASSWORD_HASH='$argon2id$v=19$m=19456,t=2,p=1$salt$hash' \
  -e SKS5_LOG_FORMAT=json \
  -e SKS5_BAN_ENABLED=true \
  -e SKS5_IP_GUARD_ENABLED=true \
  -e SKS5_GLOBAL_ACL_DENY="169.254.169.254:*" \
  -v sks5-data:/etc/sks5 \
  sks5:latest
```

### Docker Secrets

For sensitive values, use the `_FILE` convention with Docker/Podman secrets:

**1. Create secret files:**

```bash
mkdir -p secrets
sks5 hash-password --password "alice-secret" > secrets/alice_hash.txt
openssl rand -hex 32 > secrets/api_token.txt
```

**2. Reference in docker-compose.yml:**

```yaml
services:
  sks5:
    environment:
      SKS5_USER_0_PASSWORD_HASH_FILE: /run/secrets/alice_hash
      SKS5_API_TOKEN_FILE: /run/secrets/api_token
    secrets:
      - alice_hash
      - api_token

secrets:
  alice_hash:
    file: ./secrets/alice_hash.txt
  api_token:
    file: ./secrets/api_token.txt
```

Supported `_FILE` variables: `SKS5_PASSWORD_HASH_FILE`, `SKS5_API_TOKEN_FILE`, `SKS5_TOTP_SECRET_FILE`, and their per-user indexed variants (`SKS5_USER_<N>_PASSWORD_HASH_FILE`, `SKS5_USER_<N>_TOTP_SECRET_FILE`).

### Health Checks

The Containerfile includes a built-in health check:

```dockerfile
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["sks5", "health-check", "--addr", "127.0.0.1:2222", "--timeout", "3"]
```

The docker-compose.yml adds a `start_period`:

```yaml
healthcheck:
  test: ["CMD", "sks5", "health-check", "--addr", "127.0.0.1:2222", "--timeout", "3"]
  interval: 30s
  timeout: 5s
  retries: 3
  start_period: 10s
```

When the metrics or API server is enabled, additional HTTP health probes are available:

| Endpoint | Port | Purpose | Auth |
|----------|------|---------|------|
| `/livez` | 9090, 9091 | Liveness (always 200) | No |
| `/health` | 9090 | Readiness (503 during maintenance) | No |
| `/api/health` | 9091 | Detailed health status | Yes (Bearer) |

Use `/livez` for container liveness probes and `/health` for load balancer readiness probes.

### Volume Mounts

| Path | Purpose | Mode |
|------|---------|------|
| `/etc/sks5/config.toml` | Configuration file | `ro` (read-only) |
| `/etc/sks5/keys/` or `/etc/sks5/host_key` | SSH host key (persisted across restarts) | `rw` |
| `/var/log/sks5/` | Audit logs | `rw` |
| `/etc/sks5/tls/` | TLS certificates for SOCKS5 | `ro` |
| `/var/lib/sks5/bookmarks.json` | Persistent bookmarks | `rw` |
| `/run/secrets/` | Docker/Podman secrets | auto-managed |

---

## Systemd Deployment

### Installing the Binary

Build a release binary and install it:

```bash
# Build
cargo build --release

# Or build a static binary (no shared library dependencies)
make build-static

# Install
sudo install -m 755 target/release/sks5 /usr/local/bin/sks5
```

### Creating the Service User

Create a dedicated non-login user and required directories:

```bash
sudo groupadd -r sks5
sudo useradd -r -g sks5 -d /etc/sks5 -s /usr/sbin/nologin sks5

sudo mkdir -p /etc/sks5 /var/lib/sks5 /var/log/sks5
sudo chown -R sks5:sks5 /etc/sks5 /var/lib/sks5 /var/log/sks5
sudo chmod 750 /etc/sks5 /var/lib/sks5 /var/log/sks5
```

Place your configuration file and generate the initial password:

```bash
# Generate config
sudo -u sks5 sks5 init --username admin --output /etc/sks5/config.toml

# Or copy and edit the example config
sudo cp config.example.toml /etc/sks5/config.toml
sudo chown sks5:sks5 /etc/sks5/config.toml
sudo chmod 640 /etc/sks5/config.toml
```

### Systemd Unit File

The project includes a hardened systemd unit file at `contrib/sks5.service`:

```ini
[Unit]
Description=sks5 SSH+SOCKS5 proxy server
Documentation=https://github.com/galti3r/sks5
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sks5
Group=sks5
ExecStart=/usr/local/bin/sks5 --config /etc/sks5/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

# Hardening
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
ProtectClock=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectHostname=true

# File access
ReadWritePaths=/var/lib/sks5 /var/log/sks5
ReadOnlyPaths=/etc/sks5

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

Install the unit file:

```bash
sudo cp contrib/sks5.service /etc/systemd/system/sks5.service
sudo systemctl daemon-reload
```

Key hardening features in the unit file:
- `ProtectSystem=strict`: filesystem is read-only except for explicitly allowed paths
- `ProtectHome=true`: no access to `/home`, `/root`, `/run/user`
- `NoNewPrivileges=true`: prevents privilege escalation
- `MemoryDenyWriteExecute=true`: prevents W+X memory mappings
- `RestrictAddressFamilies=AF_INET AF_INET6`: only IPv4/IPv6 sockets allowed
- `ReadWritePaths`: limited to `/var/lib/sks5` (data) and `/var/log/sks5` (logs)
- `ReadOnlyPaths=/etc/sks5`: config is read-only at runtime

### Enabling and Starting

```bash
# Enable auto-start on boot
sudo systemctl enable sks5

# Start the service
sudo systemctl start sks5

# Check status
sudo systemctl status sks5

# Reload configuration (SIGHUP)
sudo systemctl reload sks5

# Restart the service
sudo systemctl restart sks5
```

### Viewing Logs

sks5 logs to stdout/stderr, which systemd captures in the journal:

```bash
# Follow live logs
sudo journalctl -u sks5 -f

# View recent logs
sudo journalctl -u sks5 --since "1 hour ago"

# View logs in JSON format (if configured)
sudo journalctl -u sks5 -o cat

# View only error-level entries
sudo journalctl -u sks5 -p err
```

### Log Rotation

**Built-in audit log rotation:**

sks5 rotates its audit log file automatically based on configuration:

```toml
[logging]
audit_log_path = "/var/log/sks5/audit.json"
audit_max_size_mb = 100   # Rotate when file exceeds 100 MB
audit_max_files = 5        # Keep 5 rotated files
```

**External logrotate (for journald output redirected to files):**

If you redirect journald output to a file, configure logrotate:

```
/var/log/sks5/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 sks5 sks5
    postrotate
        systemctl reload sks5 2>/dev/null || true
    endscript
}
```

Install the logrotate config:

```bash
sudo cp contrib/sks5.logrotate /etc/logrotate.d/sks5
```

---

## Monitoring Setup

### Prometheus Scrape Config

Add sks5 to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'sks5'
    scrape_interval: 15s
    static_configs:
      - targets: ['sks5-host:9090']
    # If metrics server requires no auth (default)
    # For API server, add bearer_token for /api endpoints
```

If you use the API server metrics instead:

```yaml
scrape_configs:
  - job_name: 'sks5-api'
    scrape_interval: 15s
    static_configs:
      - targets: ['sks5-host:9091']
    bearer_token: 'your-api-token'
    metrics_path: '/api/status'
```

### Key Metrics

Monitor these core metrics for production operations:

| Metric | Type | Description |
|--------|------|-------------|
| `sks5_connections_active` | Gauge | Current number of active connections |
| `sks5_connections_total` | Counter | Total connections since start |
| `sks5_bytes_sent_total` | Counter | Total bytes sent (per user label) |
| `sks5_bytes_received_total` | Counter | Total bytes received (per user label) |
| `sks5_auth_success_total` | Counter | Total successful authentications |
| `sks5_auth_failure_total` | Counter | Total failed authentication attempts |
| `sks5_bans_total` | Counter | Total IP bans issued |
| `sks5_acl_denied_total` | Counter | Total ACL-denied connections |
| `sks5_audit_events_dropped_total` | Counter | Audit events lost due to channel overflow |

The `max_metric_labels` setting (default 100) caps the number of distinct user labels. Beyond this limit, new users are aggregated under the `_other` label to prevent label cardinality explosion.

### Grafana Dashboard Suggestions

Create a Grafana dashboard with these panels:

**Overview row:**
- Active connections (gauge, `sks5_connections_active`)
- Connections per second (rate, `rate(sks5_connections_total[5m])`)
- Auth failure rate (rate, `rate(sks5_auth_failure_total[5m])`)
- Active bans count (gauge from API)

**Traffic row:**
- Bandwidth sent/received (rate, `rate(sks5_bytes_sent_total[5m])`)
- Bandwidth by user (stacked area, `rate(sks5_bytes_sent_total[5m])` grouped by user label)
- Connection duration histogram

**Security row:**
- Auth failures over time (time series, `rate(sks5_auth_failure_total[1m])`)
- Ban events (time series, `rate(sks5_bans_total[5m])`)
- ACL denials (time series, `rate(sks5_acl_denied_total[5m])`)
- Dropped audit events (counter, `sks5_audit_events_dropped_total`)

**Per-user row:**
- Top users by bandwidth (top N table)
- Top users by connections (top N table)
- Quota usage percentages

### Alerting with Webhooks

sks5 has a built-in alerting engine. Configure alert rules to fire webhooks:

```toml
[alerting]
enabled = true

[[alerting.rules]]
name = "high_auth_failures"
condition = "auth_failures"
threshold = 100
window_secs = 300
webhook_url = "https://hooks.slack.com/services/T.../B.../xxx"

[[alerting.rules]]
name = "bandwidth_spike"
condition = "bandwidth_exceeded"
threshold = 10737418240  # 10 GB
window_secs = 3600
webhook_url = "https://hooks.pagerduty.com/xxx"
```

You can also use the webhook system for general event notification and integrate with external monitoring:

```toml
[[webhooks]]
url = "https://your-monitoring.example.com/ingest"
events = ["auth_failure", "ban", "connection_open", "connection_close"]
secret = "webhook-hmac-secret"
max_retries = 3
```

---

## Backup and Restore

### CLI Backup

Export server state (bans, quota usage) via the management API:

```bash
# Backup to a file
sks5 backup --token YOUR_API_TOKEN --output backup.json

# Backup with custom API address
sks5 backup --token YOUR_API_TOKEN --api-addr http://10.0.0.1:9091 --output backup.json

# Backup to stdout (for piping)
sks5 backup --token YOUR_API_TOKEN
```

### CLI Restore

Import a backup file to restore server state:

```bash
# Restore from a file
sks5 restore --token YOUR_API_TOKEN --input backup.json

# Restore with custom API address
sks5 restore --token YOUR_API_TOKEN --api-addr http://10.0.0.1:9091 --input backup.json
```

### Automating with Cron

Schedule regular backups using cron:

```bash
# Edit crontab
crontab -e

# Add daily backup at 3 AM
0 3 * * * /usr/local/bin/sks5 backup --token YOUR_TOKEN --output /var/backups/sks5/backup-$(date +\%Y\%m\%d).json 2>/dev/null

# Clean up backups older than 30 days
0 4 * * * find /var/backups/sks5 -name "backup-*.json" -mtime +30 -delete
```

Ensure the backup directory exists and has appropriate permissions:

```bash
sudo mkdir -p /var/backups/sks5
sudo chown sks5:sks5 /var/backups/sks5
sudo chmod 750 /var/backups/sks5
```

### What Gets Backed Up

The backup includes runtime state that is not stored in the config file:

| Data | Description |
|------|-------------|
| Ban list | Currently banned IPs with expiration times |
| Quota usage | Per-user daily/monthly/hourly/total bandwidth and connection counters |

The backup does **not** include:
- Configuration (use version control for your config file)
- SSH host keys (back these up separately)
- Audit logs (use standard log backup procedures)
- Active connections (transient state)

---

## High Availability Notes

### Single-Instance Design

sks5 is designed as a single-instance server. It keeps all state (connections, bans, quotas, sessions) in-memory. There is no built-in clustering or state replication.

### Reliability with Systemd

Use systemd restart policies for automatic recovery:

```ini
[Service]
Restart=on-failure
RestartSec=5
```

This restarts sks5 within 5 seconds if it crashes. The `on-failure` policy restarts only on non-zero exit codes (not on clean shutdown via SIGTERM).

### Graceful Shutdown

sks5 supports graceful shutdown. When receiving SIGTERM:

1. Stop accepting new connections
2. Drain active connections for up to `shutdown_timeout` seconds (default 30)
3. Force-close remaining connections after the timeout

```toml
[server]
shutdown_timeout = 30  # seconds
```

### Hot Configuration Reload

Configuration can be reloaded without restarting:

```bash
# Via systemd
sudo systemctl reload sks5

# Via SIGHUP signal
kill -HUP $(pidof sks5)

# Via API
curl -X POST -H "Authorization: Bearer $TOKEN" http://localhost:9091/api/reload
```

Hot reload updates users, ACL rules, limits, and most settings. It does **not** change the SSH listen address or host key.

### Load Balancer Considerations

If placing sks5 behind a load balancer:

- **SSH traffic**: Use TCP-mode load balancing (not HTTP). SSH is a stateful protocol.
- **SOCKS5 traffic**: Requires sticky sessions (session affinity) since SOCKS5 connections are stateful.
- **Health probes**: Use `/livez` (always 200) for liveness and `/health` (503 during maintenance) for readiness.
- **Maintenance mode**: Toggle maintenance via `POST /api/maintenance`. The `/health` endpoint returns 503 during maintenance, allowing the load balancer to drain traffic.

### Scaling Beyond a Single Instance

For deployments requiring more than one instance:

- Run multiple independent sks5 instances behind a TCP load balancer
- Each instance has its own ban list and quota state (not shared)
- Use consistent hashing or source-IP-based routing for sticky sessions
- Synchronize configuration files via your deployment pipeline (Ansible, Terraform, etc.)
- Use centralized monitoring (Prometheus + Grafana) to aggregate metrics from all instances
- Bans are per-instance; consider an external ban list (firewall rules) for coordinated blocking
