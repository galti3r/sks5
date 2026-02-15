#!/bin/bash
# E2E test runner using Podman containers
# Tests sks5 in an isolated network environment

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NETWORK_NAME="sks5-test-net"
SERVER_NAME="sks5-server"
CLIENT_NAME="sks5-test-client"

cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"
    podman rm -f "$SERVER_NAME" 2>/dev/null || true
    podman rm -f "$CLIENT_NAME" 2>/dev/null || true
    podman network rm "$NETWORK_NAME" 2>/dev/null || true
    echo -e "${GREEN}Cleanup done${NC}"
}

trap cleanup EXIT

echo "========================================="
echo "  sks5 E2E Tests (Podman)"
echo "========================================="
echo ""

# 1. Build sks5 server image
echo -e "${YELLOW}[1/5] Building sks5 server image...${NC}"
podman build -t sks5:test -f "$PROJECT_DIR/Containerfile" "$PROJECT_DIR"
echo -e "${GREEN}  ✓ Server image built${NC}"

# 2. Build test client image
echo -e "${YELLOW}[2/5] Building test client image...${NC}"
podman build -t sks5-test-client:latest -f "$PROJECT_DIR/tests/Containerfile.test-client" "$PROJECT_DIR/tests"
echo -e "${GREEN}  ✓ Client image built${NC}"

# 3. Create test network
echo -e "${YELLOW}[3/5] Creating test network...${NC}"
podman network rm "$NETWORK_NAME" 2>/dev/null || true
podman network create "$NETWORK_NAME"
echo -e "${GREEN}  ✓ Network created${NC}"

# 4. Generate test config and start server
echo -e "${YELLOW}[4/5] Starting sks5 server...${NC}"

TEMP_DIR=$(mktemp -d)
PASS_HASH=$(cd "$PROJECT_DIR" && cargo run --quiet -- hash-password --password testpass 2>/dev/null || echo '$argon2id$v=19$m=19456,t=2,p=1$fakesalt$fakehash')

cat > "$TEMP_DIR/config.toml" << TOML
[server]
ssh_listen = "0.0.0.0:2222"

[shell]
hostname = "sks5-container"

[security]
ip_guard_enabled = false

[logging]
level = "debug"

[[users]]
username = "testuser"
password_hash = "$PASS_HASH"
TOML

podman run -d \
    --name "$SERVER_NAME" \
    --network "$NETWORK_NAME" \
    -v "$TEMP_DIR/config.toml:/etc/sks5/config.toml:ro" \
    sks5:test

# Wait for server to be ready
echo "  Waiting for server to start..."
sleep 3

if podman logs "$SERVER_NAME" 2>&1 | grep -q "listening\|started\|bound"; then
    echo -e "${GREEN}  ✓ Server started${NC}"
else
    echo -e "${YELLOW}  ⚠ Server may not be ready, continuing anyway...${NC}"
    podman logs "$SERVER_NAME" 2>&1 | tail -5
fi

# 5. Run tests from client container
echo -e "${YELLOW}[5/5] Running E2E tests...${NC}"

podman run --rm \
    --name "$CLIENT_NAME" \
    --network "$NETWORK_NAME" \
    sks5-test-client:latest \
    /bin/bash /tests/run-e2e-in-container.sh "$SERVER_NAME" 2222 testuser testpass

echo ""
echo "========================================="
echo -e "${GREEN}  All container E2E tests passed!${NC}"
echo "========================================="
