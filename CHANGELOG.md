# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Project renamed from `s5` / `s5-proxy` to `sks5`**. Binary: `s5` -> `sks5`. Crate: `s5-proxy` -> `sks5`. Env vars prefix: `S5_` -> `SKS5_`. Paths: `/etc/s5/` -> `/etc/sks5/`. GitHub: `galti3r/s5` -> `galti3r/sks5`. Docker Hub: `dockerhubgalti3r/sks5`. GHCR: `ghcr.io/galti3r/sks5`. Homebrew: `galti3r/homebrew-sks5`, formula `sks5`.

### Added
- SSH server with password, public key, and certificate authentication
- SOCKS5 standalone proxy with username/password auth
- Dynamic SOCKS5 forwarding via SSH (`ssh -D`)
- Local port forwarding via SSH (`ssh -L`)
- Virtual shell emulation with built-in commands
- Multi-user support with per-user ACL and quotas
- Global and per-user ACL rules (hostname, CIDR, port ranges, wildcards)
- Argon2id password hashing
- TOTP two-factor authentication
- Auto-ban (fail2ban-style) with configurable thresholds
- IP reputation scoring
- Multi-window rate limiting (per-second, per-minute, per-hour)
- Bandwidth quotas (daily, monthly, hourly, lifetime)
- Connection quotas (daily, monthly)
- REST API with bearer token authentication
- Real-time dashboard with Server-Sent Events
- Prometheus metrics with cardinality protection
- Audit logging with file rotation
- Webhook notifications with HMAC signatures and retry
- Alert engine with configurable rules
- GeoIP filtering (country allow/deny)
- DNS caching with configurable TTL
- Smart connection retry with exponential backoff
- Connection pooling (per-host LIFO)
- SSRF protection (IP guard)
- Upstream SOCKS5 proxy chaining
- TLS support for standalone SOCKS5
- PROXY protocol support
- Shell completions (bash, zsh, fish)
- Man page generation
- Config presets (bastion, proxy, dev)
- Show-config command with sensitive field redaction
- Backup/restore API for bans and quotas
- WebSocket bidirectional dashboard updates
- Light/dark theme toggle for dashboard
- Cursor-based API pagination
- UDP relay support (SOCKS5 UDP ASSOCIATE)
- Systemd unit file with hardening
- Docker/Podman multi-arch container images
- Configuration via environment variables
- Docker/Kubernetes secrets via `_FILE` convention
- Health check CLI command
- Zero-config quick-start mode
- Config generation with `init` command
- SSH config snippet generator
- Scheduled maintenance windows
- Group-based configuration inheritance
- Shell bookmarks and aliases
- Idle timeout warnings
- Time-based access restrictions
- Auth method chaining
- Delegated admin role
- Per-user shell command permissions

## [0.1.0] - 2024-01-01

### Added
- Initial release with all core features
