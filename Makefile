SHELL := /bin/bash

# Detect host architecture for musl target
MUSL_TARGET := $(shell uname -m | sed 's/x86_64/x86_64-unknown-linux-musl/' | sed 's/aarch64/aarch64-unknown-linux-musl/')

.PHONY: build build-debug build-static test test-unit test-e2e test-e2e-all test-e2e-browser test-screenshots test-perf test-e2e-podman test-compose test-compose-validate coverage run fmt clippy check docker-build docker-build-scratch docker-build-all docker-build-cross docker-build-multiarch docker-build-package docker-scan docker-build-scan docker-run docker-run-scratch compose-up compose-down hash-password clean security-scan test-all quick-start init completions manpage bench changelog install-act ensure-podman-socket ci-lint ci-test ci-docker-lint ci-e2e ci validate validate-docker validate-ci validate-msrv validate-coverage validate-security setup

build:
	cargo build --release

build-debug:
	cargo build

build-static:
	rustup target add $(MUSL_TARGET) 2>/dev/null || true
	cargo build --release --target $(MUSL_TARGET)
	@echo "Static binary: target/$(MUSL_TARGET)/release/sks5"

test:
	cargo test --all-targets

test-unit:
	cargo test --lib

test-e2e:
	cargo test --test '*'

test-e2e-all:
	cargo test --test '*'

test-e2e-browser:
	@command -v podman >/dev/null 2>&1 || { echo "Error: podman is required for browser E2E tests"; exit 1; }
	@podman image exists docker.io/chromedp/headless-shell:latest 2>/dev/null || \
		{ echo "Pulling chromedp/headless-shell..."; podman pull docker.io/chromedp/headless-shell:latest; }
	@status=0; \
	cargo test --test e2e_browser_dashboard -- --nocapture || status=$$?; \
	podman ps -aq --filter "name=sks5-chrome" | xargs -r podman stop 2>/dev/null || true; \
	exit $$status

test-screenshots:
	@command -v podman >/dev/null 2>&1 || { echo "Error: podman is required for screenshot tests"; exit 1; }
	@podman image exists docker.io/chromedp/headless-shell:latest 2>/dev/null || \
		{ echo "Pulling chromedp/headless-shell..."; podman pull docker.io/chromedp/headless-shell:latest; }
	@mkdir -p screenshots
	@status=0; \
	SCREENSHOT_DIR=screenshots cargo test --test e2e_browser_screenshots -- --nocapture || status=$$?; \
	podman ps -aq --filter "name=sks5-chrome" | xargs -r podman stop 2>/dev/null || true; \
	exit $$status

test-perf:
	cargo test --test e2e_performance -- --nocapture

test-e2e-podman:
	./scripts/test-e2e-podman.sh

test-compose:
	./scripts/test-compose.sh

test-compose-validate:
	podman-compose config

test-all: test security-scan

coverage:
	cargo llvm-cov --all-targets

run:
	cargo run -- --config config.example.toml

fmt:
	cargo fmt

clippy:
	cargo clippy --all-targets -- -D warnings

check:
	cargo check --all-targets

security-scan:
	./scripts/security-scan.sh

validate-msrv:
	@rustup toolchain list | grep -q '^1\.88' || rustup toolchain install 1.88
	cargo +1.88 check

validate-coverage:
	@rustup component add llvm-tools-preview 2>/dev/null || true
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked
	cargo llvm-cov --lcov --output-path lcov.info --lib --test unit

validate-security:
	@cargo audit
	@cargo deny check

docker-build:
	podman build -f Containerfile.alpine -t sks5:latest -t sks5:alpine .

docker-build-scratch:
	podman build -t sks5:scratch .

docker-build-all: docker-build docker-build-scratch
	@echo "Built sks5:latest (alpine, default) and sks5:scratch"

docker-scan: ensure-podman-socket
	@command -v trivy >/dev/null 2>&1 || { echo "Install trivy: https://trivy.dev"; exit 1; }
	trivy image --image-src podman --exit-code 1 --severity CRITICAL,HIGH sks5:latest
	trivy image --image-src podman --exit-code 1 --severity CRITICAL,HIGH sks5:scratch

docker-build-scan: docker-build-all docker-scan

docker-build-cross:
	./scripts/build-multiarch-cross.sh

docker-build-multiarch:
	./scripts/build-multiarch-qemu.sh

docker-build-package:
	@echo "Building multi-arch image from pre-built binaries..."
	@test -f binaries/amd64/sks5 || { echo "Error: binaries/amd64/sks5 not found. Run 'make build-static' first."; exit 1; }
	@test -f binaries/arm64/sks5 || { echo "Error: binaries/arm64/sks5 not found. Cross-compile for aarch64 first."; exit 1; }
	podman build -f Containerfile.package --target alpine -t sks5:latest -t sks5:alpine .
	podman build -f Containerfile.package --target minimal -t sks5:scratch .

docker-run:
	podman run --rm -p 2222:2222 -p 1080:1080 \
		-v ./config.example.toml:/etc/sks5/config.toml:ro sks5:latest

docker-run-scratch:
	podman run --rm -p 2222:2222 -p 1080:1080 \
		-v ./config.example.toml:/etc/sks5/config.toml:ro sks5:scratch

compose-up:
	podman-compose up -d

compose-down:
	podman-compose down

hash-password:
	@read -sp "Enter password: " pass && echo && \
	hash=$$(cargo run --quiet -- hash-password --password "$$pass") && \
	echo "" && \
	echo "password_hash = \"$$hash\""

quick-start:
	cargo run -- quick-start --password demo

init:
	cargo run -- init --password demo --output config.toml

completions:
	@mkdir -p completions
	cargo run --quiet -- completions bash > completions/sks5.bash
	cargo run --quiet -- completions zsh > completions/_sks5
	cargo run --quiet -- completions fish > completions/sks5.fish
	@echo "Shell completions generated in completions/"

manpage:
	@mkdir -p man
	cargo run --quiet -- manpage > man/sks5.1
	@echo "Man page generated: man/sks5.1"

bench:
	cargo bench

changelog:
	git-cliff --output CHANGELOG.md

clean:
	cargo clean

# ===========================================================================
# Local CI with act + Podman
# ===========================================================================

setup:
	@echo "Installing all development tools..."
	@mkdir -p ~/.local/bin
	@# act (local CI runner)
	@command -v act >/dev/null 2>&1 && echo "  ok act" || \
		{ echo "  .. act"; curl -fsSL https://raw.githubusercontent.com/nektos/act/master/install.sh | bash -s -- -b ~/.local/bin 2>/dev/null && echo "  ok act (installed)" || echo "  !! act (failed)"; }
	@# cargo tools
	@command -v cargo-audit >/dev/null 2>&1 && echo "  ok cargo-audit" || \
		{ echo "  .. cargo-audit"; cargo install cargo-audit --locked 2>/dev/null && echo "  ok cargo-audit (installed)" || echo "  !! cargo-audit (failed)"; }
	@command -v cargo-deny >/dev/null 2>&1 && echo "  ok cargo-deny" || \
		{ echo "  .. cargo-deny"; cargo install cargo-deny --locked 2>/dev/null && echo "  ok cargo-deny (installed)" || echo "  !! cargo-deny (failed)"; }
	@command -v cargo-llvm-cov >/dev/null 2>&1 && echo "  ok cargo-llvm-cov" || \
		{ echo "  .. cargo-llvm-cov"; rustup component add llvm-tools-preview 2>/dev/null; cargo install cargo-llvm-cov --locked 2>/dev/null && echo "  ok cargo-llvm-cov (installed)" || echo "  !! cargo-llvm-cov (failed)"; }
	@# MSRV toolchain
	@rustup toolchain list 2>/dev/null | grep -q '^1\.88' && echo "  ok MSRV 1.88" || \
		{ echo "  .. MSRV 1.88"; rustup toolchain install 1.88 2>/dev/null && echo "  ok MSRV 1.88 (installed)" || echo "  !! MSRV 1.88 (failed)"; }
	@# trivy: binary install → podman wrapper → docker wrapper
	@command -v trivy >/dev/null 2>&1 && echo "  ok trivy (native)" || \
		{ echo "  .. trivy"; \
		  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh 2>/dev/null | sh -s -- -b ~/.local/bin 2>/dev/null \
		  && echo "  ok trivy (installed)" \
		  || { if command -v podman >/dev/null 2>&1; then \
		         echo "  .. trivy binary failed, creating podman wrapper"; \
		         printf '#!/bin/sh\nexec podman run --rm -v "$${XDG_RUNTIME_DIR}/podman/podman.sock:/var/run/docker.sock:ro" ghcr.io/aquasecurity/trivy:latest "$$@"\n' > ~/.local/bin/trivy \
		         && chmod +x ~/.local/bin/trivy \
		         && echo "  ok trivy (podman wrapper)"; \
		       elif command -v docker >/dev/null 2>&1; then \
		         echo "  .. trivy binary failed, creating docker wrapper"; \
		         printf '#!/bin/sh\nexec docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro ghcr.io/aquasecurity/trivy:latest "$$@"\n' > ~/.local/bin/trivy \
		         && chmod +x ~/.local/bin/trivy \
		         && echo "  ok trivy (docker wrapper)"; \
		       else \
		         echo "  !! trivy (no binary, no podman, no docker)"; \
		       fi; }; }
	@# vhs: go install → podman wrapper → docker wrapper
	@command -v vhs >/dev/null 2>&1 && echo "  ok vhs (native)" || \
		{ echo "  .. vhs"; \
		  if command -v go >/dev/null 2>&1; then \
		    go install github.com/charmbracelet/vhs@latest 2>/dev/null && echo "  ok vhs (installed)" && exit 0; \
		  fi; \
		  if command -v podman >/dev/null 2>&1; then \
		    echo "  .. creating podman wrapper"; \
		    printf '#!/bin/sh\nexec podman run --rm -v "$$PWD:/vhs" ghcr.io/charmbracelet/vhs "$$@"\n' > ~/.local/bin/vhs \
		    && chmod +x ~/.local/bin/vhs \
		    && echo "  ok vhs (podman wrapper)"; \
		  elif command -v docker >/dev/null 2>&1; then \
		    echo "  .. creating docker wrapper"; \
		    printf '#!/bin/sh\nexec docker run --rm -v "$$PWD:/vhs" ghcr.io/charmbracelet/vhs "$$@"\n' > ~/.local/bin/vhs \
		    && chmod +x ~/.local/bin/vhs \
		    && echo "  ok vhs (docker wrapper)"; \
		  else \
		    echo "  !! vhs (no binary, no podman, no docker)"; \
		  fi; }
	@echo ""
	@echo "Done. Re-run 'make validate-docker' to verify."

install-act:
	@echo "Installing act to ~/.local/bin..."
	@mkdir -p ~/.local/bin
	@curl -fsSL https://raw.githubusercontent.com/nektos/act/master/install.sh | bash -s -- -b ~/.local/bin
	@echo "act installed: $$(~/.local/bin/act --version)"

ensure-podman-socket:
	@systemctl --user is-active podman.socket >/dev/null 2>&1 || \
		{ echo "Starting Podman socket..."; systemctl --user start podman.socket; }
	@test -S "$${XDG_RUNTIME_DIR}/podman/podman.sock" || \
		{ echo "Error: Podman socket not found at $${XDG_RUNTIME_DIR}/podman/podman.sock"; exit 1; }

ci-lint: ensure-podman-socket
	DOCKER_HOST="unix://$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		act push -j lint \
		--container-daemon-socket "$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		--eventpath .github/act-event.json \
		--env RUST_BACKTRACE=1

ci-test: ensure-podman-socket
	DOCKER_HOST="unix://$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		act push -j test \
		--container-daemon-socket "$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		--eventpath .github/act-event.json \
		--env RUST_BACKTRACE=1

ci-docker-lint: ensure-podman-socket
	DOCKER_HOST="unix://$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		act push -j docker-lint \
		--container-daemon-socket "$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		--eventpath .github/act-event.json

ci-e2e: ensure-podman-socket
	DOCKER_HOST="unix://$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		act push -j e2e-tests \
		--container-daemon-socket "$${XDG_RUNTIME_DIR}/podman/podman.sock" \
		--eventpath .github/act-event.json \
		--env RUST_BACKTRACE=1

ci: ci-lint ci-test ci-e2e ci-docker-lint
	@echo "Local CI passed (lint + test + e2e + docker-lint)"

validate:
	@./scripts/validate.sh

validate-docker:
	@./scripts/validate.sh --with-docker

# Sequential CI reproduction (kept for backwards compatibility)
validate-ci: ci-lint ci-test ci-e2e ci-docker-lint
	@echo "CI reproduction passed (via act)"
