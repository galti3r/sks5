# Contributing to sks5

## Getting Started

1. Clone the repository
2. Install Rust 1.88+ (MSRV)
3. Build and run tests:
   ```bash
   cargo build
   cargo test --all-targets
   ```

---

## Pull Request Checklist

Before submitting a PR, ensure all of the following pass:

- [ ] `cargo fmt --all -- --check` (no formatting issues)
- [ ] `cargo clippy --all-targets -- -D warnings` (no lint warnings)
- [ ] `cargo test --all-targets` (all tests pass)
- [ ] `cargo test --test e2e_browser_dashboard -- --ignored` (browser E2E tests pass, requires Podman)
- [ ] Code coverage remains at **90% minimum** (`cargo tarpaulin --all-targets --fail-under 90`)
- [ ] New code has accompanying tests
- [ ] No commented-out code in the diff
- [ ] No secrets, credentials, or API keys in the diff

Quick validation:

```bash
# Full check
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings && cargo test --all-targets

# With browser E2E
make test && make test-e2e-browser
```

---

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). PR commits are validated by commitlint in CI.

### Format

```
<type>: <short description>

<optional body>

<optional footer>
```

### Types

| Type | Description | Example |
|------|-------------|---------|
| `feat` | New feature | `feat: add UDP relay support` |
| `fix` | Bug fix | `fix: prevent double-ban on concurrent auth failures` |
| `docs` | Documentation | `docs: add CI/CD architecture guide` |
| `test` | Test additions/changes | `test: add ACL CIDR property-based tests` |
| `refactor` | Code restructuring (no behavior change) | `refactor: extract SecurityManager from server.rs` |
| `perf` | Performance improvement | `perf: use DashMap for concurrent ban lookups` |
| `chore` | Build, deps, tooling | `chore: bump russh to 0.46` |
| `ci` | CI/CD pipeline changes | `ci: add Forgejo Actions workflow` |

### Rules

- Use imperative mood: "add feature" not "added feature"
- First line under 72 characters
- Reference issues when applicable: `fix: resolve auth race condition (closes #42)`

---

## Code Style

### Rust

- Follow `rustfmt` defaults (no custom `.rustfmt.toml`)
- All public items must have doc comments
- Comments in English; explain "why", not "what"
- Error types use `thiserror`; propagate context (no empty `catch`/`unwrap` in production code)
- Use `tracing` for structured logging with appropriate levels (DEBUG/INFO/WARN/ERROR)
- Never log sensitive data (passwords, tokens, keys)
- Pin dependency versions explicitly in `Cargo.toml`

### TOML Config Strings in Tests

Due to Rust 2021 edition behavior with `$identifier` in string literals, test TOML configs must use `r##"..."##` (double `#`) or `format!()`:

```rust
// Good
let toml = r##"
[server]
ssh_listen = "0.0.0.0:2222"
"##;

// Good
let toml = format!(r#"
[[users]]
password_hash = "{}"
"#, hash);

// Bad -- $hash triggers Rust 2021 prefix error
let toml = r#"
password_hash = "$argon2id$..."
"#;
```

---

## Adding Tests

### Requirements

- Every new feature must include unit tests
- Every bug fix must include a regression test
- E2E tests for user-facing behavior changes
- Coverage target: **90% minimum** (enforced in CI)

### Test Types

| Type | Location | When to Add |
|------|----------|-------------|
| Unit | `tests/unit/<module>_test.rs` | Isolated logic, parsing, validation |
| E2E | `tests/e2e/<feature>_test.rs` | Real server interaction, client behavior |
| Property-based | `tests/unit/<module>_proptest.rs` | Parsers, serialization, edge cases |
| Browser E2E | `tests/e2e/browser_dashboard_test.rs` | Dashboard UI changes |
| Benchmarks | `benches/<module>_bench.rs` | Performance-critical code paths |

### Registering New Test Files

Every test file in `tests/` must have a corresponding `[[test]]` entry in `Cargo.toml`:

```toml
[[test]]
name = "unit_my_feature"
path = "tests/unit/my_feature_test.rs"
```

See [docs/TESTING.md](docs/TESTING.md) for the full testing guide.

---

## Browser E2E Tests

Browser tests are **mandatory** for any dashboard UI changes. They require:

- **Podman** installed and available in `$PATH`
- The Chrome Headless image: `docker.io/chromedp/headless-shell:latest`

Run them with:

```bash
make test-e2e-browser
```

Tests use `chromiumoxide` to control Chrome via the DevTools Protocol. They start a real sks5 server, open the dashboard in Chrome, and validate DOM state.

If you cannot run Podman locally (e.g. macOS without a Podman machine), the CI will run them for you. Mark your PR and note that browser tests were not run locally.

---

## Security

### Dependency Changes

When adding or updating a dependency:

1. Document why the dependency is needed (in the PR description and `Cargo.toml` comment)
2. Pin the version explicitly (no `^` or `~` without reason)
3. Run `cargo audit` and `cargo deny check` to verify no known vulnerabilities
4. Verify the license is compatible (checked by `cargo-deny`, config in `deny.toml`)

### Sensitive Data

- Never commit secrets, API keys, or credentials
- Use `_FILE` convention for Docker/K8s secrets
- Passwords in test configs must use pre-computed hashes, not real passwords
- SOCKS5 passwords use `zeroize` for secure memory handling

---

## Architecture

Before making structural changes, review [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module layout and design decisions.

Key principles:
- **Shared ProxyEngine**: All forwarding paths (SSH -D, SSH -L, SOCKS5) converge to `ProxyEngine`
- **RAII ConnectionGuard**: Connection counters auto-decrement on drop
- **SecurityManager::pre_auth_check()**: Shared IP validation for SSH and SOCKS5
- **Virtual filesystem**: Shell exposes zero real files

---

## Documentation

- Update `README.md` if adding user-facing features
- Update `docs/CONFIG-REFERENCE.md` if adding config fields
- Update `config.example.toml` with new config sections
- Update `docs/ARCHITECTURE.md` for structural changes
- Add entries to `docs/BUGS.md` for discovered bugs (use the template)

---

## Release Process

Releases are automated via CI on tag pushes:

1. Update version in `Cargo.toml`
2. Commit: `chore: release v1.2.3`
3. Tag: `git tag v1.2.3`
4. Push: `git push && git push --tags`

CI will build release binaries (4 targets), generate SBOM + checksums, and create a GitHub Release. See [docs/CI-CD.md](docs/CI-CD.md) for details.
