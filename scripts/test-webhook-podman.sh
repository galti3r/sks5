#!/usr/bin/env bash
# Webhook E2E test runner
# Builds sks5 image and runs the Rust webhook E2E tests
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "========================================="
echo "  sks5 Webhook E2E Test (Podman)"
echo "========================================="
echo ""

# 1. Build sks5 image
echo -e "${YELLOW}[1/2] Building sks5 image...${NC}"
podman build -t sks5-test -f "$PROJECT_DIR/Containerfile" "$PROJECT_DIR"
echo -e "${GREEN}  Server image built${NC}"

# 2. Run Rust E2E webhook tests
echo -e "${YELLOW}[2/2] Running Rust E2E webhook tests...${NC}"
cd "$PROJECT_DIR"
cargo test --test e2e_webhook -- --nocapture

echo ""
echo "========================================="
echo -e "${GREEN}  All webhook tests passed!${NC}"
echo "========================================="
