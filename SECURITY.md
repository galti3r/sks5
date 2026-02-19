# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous releases | No |

Only the latest release receives security patches. We recommend always running the most recent version.

## Reporting a Vulnerability

**Do NOT open a public issue for security vulnerabilities.**

To report a vulnerability, use one of these channels:

1. **GitHub Private Vulnerability Reporting** (preferred): Go to the [Security Advisories](https://github.com/galti3r/sks5/security/advisories) page and click "Report a vulnerability"
2. **Email**: Send details to the maintainers listed in `Cargo.toml`

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

### Response timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 7 days |
| Fix for CRITICAL/HIGH | Within 14 days |
| Fix for MEDIUM/LOW | Within 30 days |

We will coordinate disclosure with the reporter and credit them (unless they prefer anonymity).

## Security Model

sks5 is a multi-user SSH server with SOCKS5 proxy capability. Its security design includes:

- **Authentication**: Argon2id password hashing (OWASP parameters), SSH public key, SSH certificate (CA-signed), TOTP 2FA with replay protection
- **Authorization**: Per-user ACL with deny-first evaluation, CIDR and hostname pattern matching, port ranges
- **Network security**: Anti-SSRF IP guard (blocks private/reserved/CGNAT/6to4 ranges), IPv4-mapped IPv6 normalization, domain validation per RFC 1035
- **Transport**: SSH encryption via russh, optional TLS for standalone SOCKS5
- **API security**: Bearer token with constant-time comparison, HMAC-SHA256 SSE/WebSocket tickets with replay protection
- **Rate limiting**: Per-IP pre-auth and per-user post-auth, configurable multi-window (per-second, per-minute, per-hour)
- **Ban system**: Fail2ban-style auto-banning with capacity bounds, IP reputation scoring with exponential decay

For the full security audit report, see [`docs/SECURITY-AUDIT.md`](docs/SECURITY-AUDIT.md).

## Supply Chain Security

- All releases are **signed with cosign** (Sigstore keyless)
- **SLSA provenance attestation** for build verification
- **SBOM** (CycloneDX) published with each release
- Dependencies audited via `cargo audit` and `cargo deny` in CI
- Container images scanned with **Trivy** and **Grype**
- OpenSSL is explicitly banned; TLS via rustls only
- All dependencies sourced from crates.io (no git/unknown registries)

### Verifying releases

```bash
# Verify container image signature
cosign verify --certificate-identity-regexp='github.com/galti3r/sks5' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/galti3r/sks5:latest

# Verify SLSA provenance
gh attestation verify oci://ghcr.io/galti3r/sks5:latest --owner galti3r
```

## Hardening Guide

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for production deployment checklists, systemd hardening, and recommended configuration.

Key recommendations:
- Set a strong, random `api.token` (minimum 32 characters)
- Use TLS termination (reverse proxy) in front of the API server
- Enable `ban_enabled = true` with appropriate thresholds
- Set `ip_guard_enabled = true` in production
- Use `default_policy = "deny"` with explicit allow rules
- Protect config files with filesystem permissions (contains password hashes and TOTP secrets)

## Accepted Advisories

Known advisories that have been evaluated and accepted are tracked in:
- [`deny.toml`](deny.toml) -- cargo-deny advisory ignore list with justifications
- [`.cargo/audit.toml`](.cargo/audit.toml) -- cargo-audit ignore list
- [`.trivyignore`](.trivyignore) and [`.grype.yaml`](.grype.yaml) -- container scan ignores
