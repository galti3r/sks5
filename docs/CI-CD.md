# sks5 CI/CD Architecture

## Overview

sks5 provides CI/CD pipelines for three platforms, all with the same core stages:

| Platform | Config | Registry |
|----------|--------|----------|
| **GitHub Actions** | `.github/workflows/ci.yml` + `.github/workflows/release.yml` | GHCR (`ghcr.io`) |
| **GitLab CI** | `.gitlab-ci.yml` | GitLab Container Registry |
| **Forgejo Actions** | `.forgejo/workflows/ci.yml` | Forgejo Container Registry |

All pipelines enforce: lint, test, security scanning, and multi-arch Docker builds.

---

## Pipeline Stages

### 1. Lint

Runs on every push and pull request. Blocks the pipeline on failure.

| Check | Command | Purpose |
|-------|---------|---------|
| Format | `cargo fmt --all -- --check` | Consistent code formatting |
| Clippy | `cargo clippy --all-targets -- -D warnings` | Lint + deny all warnings |
| Hadolint | `hadolint Containerfile Containerfile.cross` | Dockerfile best practices |
| Commitlint | `@commitlint/config-conventional` | Conventional commit messages (GitHub PRs only) |

### 2. Test

Runs the full test suite excluding `#[ignore]` tests.

```bash
cargo test --all-targets
```

This executes all unit tests (inline + standalone), E2E tests, and property-based tests. Browser E2E and performance tests are `#[ignore]` and run in a separate job.

### 3. MSRV Verification (GitHub only)

Verifies compilation with the Minimum Supported Rust Version (1.75):

```bash
# Using Rust 1.75
cargo check --all-targets
```

This ensures backward compatibility with the declared `rust-version` in `Cargo.toml`.

### 4. Coverage

Generates code coverage using `cargo-tarpaulin` with a **90% minimum threshold**:

```bash
cargo tarpaulin --all-targets --fail-under 90 --out xml --output-dir coverage/
```

| Platform | Coverage Output |
|----------|-----------------|
| GitHub Actions | Uploaded to Codecov (`codecov/codecov-action@v4`) |
| GitLab CI | Cobertura XML report + HTML artifact; published to GitLab Pages |
| Forgejo | Not included (run locally) |

### 5. Security Scanning

Two security tools run on every pipeline:

| Tool | Command | Purpose |
|------|---------|---------|
| `cargo-audit` | `cargo audit` | Check dependencies for known vulnerabilities (RustSec advisory DB) |
| `cargo-deny` | `cargo deny check` | License compliance, advisory checks, source validation (config: `deny.toml`) |

Security scanning is **blocking** on GitHub, **allow_failure** on GitLab (to avoid blocking on transient advisory DB issues).

### 6. SARIF Upload (GitHub only)

On pushes to `main`, Clippy results are converted to SARIF format and uploaded to GitHub's Security tab:

```bash
cargo clippy --all-targets --message-format=json | clippy-sarif | sarif-fmt
```

This provides static analysis results integrated into GitHub's code scanning alerts.

### 7. Browser E2E Tests

A dedicated job runs the dashboard browser tests using Chrome Headless in Podman:

```bash
podman pull docker.io/chromedp/headless-shell:latest
cargo test --test e2e_browser_dashboard -- --ignored --nocapture
```

| Platform | Behavior |
|----------|----------|
| GitHub Actions | Podman pre-installed on `ubuntu-latest`; runs on host |
| GitLab CI | Installs Podman in Rust container; requires `privileged` runner tag; `allow_failure: true` |
| Forgejo Actions | Installs Podman on host; `continue-on-error: true` |

**Cleanup** runs unconditionally (`if: always()`) to remove leftover Chrome containers.

### 8. Docker Build & Push

Multi-architecture Docker images (linux/amd64 + linux/arm64) are built and pushed on:
- Pushes to `main`
- Tag pushes matching `v*`

**Build process:**
1. QEMU user-static emulation for cross-platform builds
2. Docker Buildx with `Containerfile.cross` (multi-stage, cross-compiled)
3. Push to platform registry with semantic version tags

**Image tags** (GitHub example):

| Tag Pattern | Example | When |
|-------------|---------|------|
| `sha-<commit>` | `sha-abc1234` | Every push to main |
| `<version>` | `1.2.3` | Tag push `v1.2.3` |
| `<major>.<minor>` | `1.2` | Tag push `v1.2.3` |
| `<major>` | `1` | Tag push `v1.2.3` |
| `latest` | `latest` | Every push (GitLab/Forgejo) |

### 9. Container Vulnerability Scanning

After Docker build, Trivy scans the container image for vulnerabilities:

```bash
trivy image --exit-code 1 --severity CRITICAL,HIGH <image>
```

Fails the pipeline on CRITICAL or HIGH severity findings.

---

## Release Pipeline (GitHub only)

Triggered by tag pushes matching `v*`. Defined in `.github/workflows/release.yml`.

### Release Stages

```
verify-version --> security --> build (4 targets) --> release
                                extras             /
                                sbom              /
```

### 1. Version Verification

Ensures the git tag matches `Cargo.toml` version:

```bash
# Tag v1.2.3 must match version = "1.2.3" in Cargo.toml
```

### 2. Cross-Compilation

Builds release binaries for four targets using [cross](https://github.com/cross-rs/cross):

| Target | Archive |
|--------|---------|
| `x86_64-unknown-linux-gnu` | `sks5-x86_64-linux-gnu.tar.gz` |
| `x86_64-unknown-linux-musl` | `sks5-x86_64-linux-musl.tar.gz` |
| `aarch64-unknown-linux-gnu` | `sks5-aarch64-linux-gnu.tar.gz` |
| `aarch64-unknown-linux-musl` | `sks5-aarch64-linux-musl.tar.gz` |

### 3. Extras

Generated alongside the release:

| Artifact | Description |
|----------|-------------|
| Shell completions | Bash, Zsh, Fish (`sks5 completions <shell>`) |
| Man page | `sks5 manpage` generates `sks5.1` |

### 4. SBOM (Software Bill of Materials)

Generates a CycloneDX SBOM in JSON format:

```bash
cargo cyclonedx --format json --output-cdx
```

The SBOM (`sks5.cdx.json`) is included in the GitHub Release for supply chain transparency.

### 5. GitHub Release

Creates a GitHub Release with:
- Auto-generated release notes
- All binary archives (4 targets)
- SHA256 checksums (`SHA256SUMS`)
- CycloneDX SBOM
- Shell completions
- Man page

### 6. Docker Release

Multi-arch Docker image pushed to GHCR with semantic version tags (`1.2.3`, `1.2`, `1`).

---

## Platform Comparison

| Feature | GitHub Actions | GitLab CI | Forgejo Actions |
|---------|:-:|:-:|:-:|
| Lint (fmt + clippy) | Yes | Yes | Yes |
| Hadolint | Yes | Yes (allow_failure) | No |
| Commitlint | PR only | No | No |
| Unit + E2E tests | Yes | Yes | Yes |
| MSRV check | Yes (1.75) | No | No |
| Coverage (tarpaulin) | Yes (90% threshold) | Yes (report) | No |
| Codecov upload | Yes | No (GitLab Pages) | No |
| Security (audit + deny) | Yes (blocking) | Yes (allow_failure) | Yes (blocking) |
| SARIF upload | Yes (push only) | No | No |
| Browser E2E | Yes | Yes (privileged) | Yes |
| Docker multi-arch | Yes | Yes | Yes |
| Trivy scan | Yes | Yes (allow_failure) | No |
| Release binaries | Yes (4 targets) | No | No |
| SBOM | Yes (CycloneDX) | No | No |
| Completions + man | Yes | No | No |

---

## Rust Toolchain

All pipelines pin Rust **1.83** for consistency:

| Platform | How |
|----------|-----|
| GitHub Actions | `dtolnay/rust-toolchain@master` with `toolchain: "1.83"` |
| GitLab CI | `rust:1.83-slim-bookworm` Docker image |
| Forgejo Actions | `rust:1.83-slim-bookworm` container or `rustup` install |

MSRV is verified separately with Rust 1.75.

---

## Caching

All pipelines cache cargo registry and build artifacts:

```
~/.cargo/registry
~/.cargo/git
target/
```

Cache keys are based on `Cargo.lock` hash to invalidate on dependency changes.

---

## Configuration Files

| File | Purpose |
|------|---------|
| `deny.toml` | `cargo-deny` configuration (licenses, advisories, sources) |
| `.hadolint.yaml` | Hadolint Dockerfile linting rules |
| `Containerfile` | Single-arch container build |
| `Containerfile.cross` | Multi-arch cross-compilation container build |
| `commitlint.config.js` | Conventional commit validation (if present) |

---

## Running CI Locally

Reproduce CI checks locally before pushing:

```bash
# Lint
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

# Test
cargo test --all-targets

# Security
cargo audit
cargo deny check

# Coverage
cargo tarpaulin --all-targets --fail-under 90

# Browser E2E
make test-e2e-browser

# Full check (tests + security)
make test-all
```
