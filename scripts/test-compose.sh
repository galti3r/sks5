#!/bin/bash
# Test docker-compose.yml services with Podman
# Tests Mode 1 (config file) and Mode 2 (env vars)
#
# TLS profile (Mode 3) is NOT tested automatically — it requires real certificates.
# To test manually:
#   mkdir -p tls && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
#     -nodes -keyout tls/socks5.key -out tls/socks5.crt -days 1 -subj '/CN=localhost'
#   mkdir -p secrets && echo "hash" > secrets/alice_hash.txt
#   podman-compose --profile tls up -d sks5-tls
#   podman-compose --profile tls down

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
SECRETS_DIR="$PROJECT_DIR/secrets"
SECRETS_CREATED=false
TEMP_COMPOSE=""
PASSED=0
FAILED=0

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    cd "$PROJECT_DIR"
    if [ -n "$TEMP_COMPOSE" ] && [ -f "$TEMP_COMPOSE" ]; then
        podman-compose -f "$TEMP_COMPOSE" down 2>/dev/null || true
        rm -f "$TEMP_COMPOSE"
        rm -f "${TEMP_COMPOSE%.yml}-env.yml"
        echo "  Removed temp compose files"
    fi
    podman-compose down 2>/dev/null || true
    if [ "$SECRETS_CREATED" = true ]; then
        rm -rf "$SECRETS_DIR"
        echo "  Removed generated secrets"
    fi
    echo -e "${GREEN}Cleanup done${NC}"
}

trap cleanup EXIT

pass() {
    echo -e "${GREEN}  PASS: $1${NC}"
    PASSED=$((PASSED + 1))
}

fail() {
    echo -e "${RED}  FAIL: $1${NC}"
    FAILED=$((FAILED + 1))
}

# Find a free port
find_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null \
        || shuf -i 30000-60000 -n 1
}

wait_healthy() {
    local container="$1"
    local timeout="${2:-30}"
    local elapsed=0

    echo "  Waiting for $container to be healthy (timeout: ${timeout}s)..."
    while [ "$elapsed" -lt "$timeout" ]; do
        local status
        status=$(podman inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "not_found")
        if [ "$status" = "healthy" ]; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo -e "${RED}  Timeout waiting for $container (last status: $status)${NC}"
    return 1
}

# Check if container is running (even without healthcheck support)
wait_running() {
    local container="$1"
    local timeout="${2:-30}"
    local elapsed=0

    echo "  Waiting for $container to be running (timeout: ${timeout}s)..."
    while [ "$elapsed" -lt "$timeout" ]; do
        local state
        state=$(podman inspect --format '{{.State.Status}}' "$container" 2>/dev/null || echo "not_found")
        if [ "$state" = "running" ]; then
            return 0
        elif [ "$state" = "exited" ] || [ "$state" = "dead" ]; then
            echo -e "${RED}  Container $container exited prematurely${NC}"
            return 1
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo -e "${RED}  Timeout waiting for $container (last state: $state)${NC}"
    return 1
}

generate_secrets() {
    if [ -d "$SECRETS_DIR" ]; then
        echo "  secrets/ directory already exists, using existing files"
        return 0
    fi

    mkdir -p "$SECRETS_DIR"
    SECRETS_CREATED=true

    echo "  Generating alice_hash.txt..."
    (cd "$PROJECT_DIR" && cargo run --quiet -- hash-password --password alicetest) > "$SECRETS_DIR/alice_hash.txt" 2>/dev/null \
        || echo '$argon2id$v=19$m=19456,t=2,p=1$fakesalt$fakehash' > "$SECRETS_DIR/alice_hash.txt"

    echo "  Generating bob_hash.txt..."
    (cd "$PROJECT_DIR" && cargo run --quiet -- hash-password --password bobtest) > "$SECRETS_DIR/bob_hash.txt" 2>/dev/null \
        || echo '$argon2id$v=19$m=19456,t=2,p=1$fakesalt$fakehash' > "$SECRETS_DIR/bob_hash.txt"

    echo "  Writing alice_totp.txt..."
    echo -n "JBSWY3DPEHPK3PXP" > "$SECRETS_DIR/alice_totp.txt"

    echo "  Writing api_token.txt..."
    echo -n "test-api-token-12345" > "$SECRETS_DIR/api_token.txt"

    echo -e "${GREEN}  Secrets generated in $SECRETS_DIR${NC}"
}

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

echo "========================================="
echo "  sks5 Compose Tests (Podman)"
echo "========================================="
echo ""

# Prerequisite: podman-compose
if ! command -v podman-compose &>/dev/null; then
    echo -e "${RED}ERROR: podman-compose is not installed${NC}"
    echo "Install with: pip install --user podman-compose"
    exit 1
fi

cd "$PROJECT_DIR"

# ---------------------------------------------------------------------------
# Allocate free ports to avoid conflicts
# ---------------------------------------------------------------------------
PORT_SSH=$(find_free_port)
PORT_SOCKS=$(find_free_port)
PORT_METRICS=$(find_free_port)
PORT_API=$(find_free_port)
echo "  Using test ports: SSH=$PORT_SSH SOCKS=$PORT_SOCKS METRICS=$PORT_METRICS API=$PORT_API"

# Generate a temp compose file with remapped ports
# (podman-compose v1.0.6 merges port lists in overrides, so we need a full replacement)
TEMP_COMPOSE="$PROJECT_DIR/docker-compose.test-tmp.yml"
sed \
    -e "s/\"2222:2222\"/\"${PORT_SSH}:2222\"/g" \
    -e "s/\"1080:1080\"/\"${PORT_SOCKS}:1080\"/g" \
    -e "s/\"9090:9090\"/\"${PORT_METRICS}:9090\"/g" \
    -e "s/\"9091:9091\"/\"${PORT_API}:9091\"/g" \
    docker-compose.yml > "$TEMP_COMPOSE"

# Helper: podman-compose with temp file
pc() {
    podman-compose -f "$TEMP_COMPOSE" "$@"
}

# ---------------------------------------------------------------------------
# Step 1: Validate compose syntax
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[1/5] Validating docker-compose.yml syntax...${NC}"
if podman-compose config >/dev/null 2>&1; then
    pass "docker-compose.yml syntax is valid"
else
    fail "docker-compose.yml syntax validation failed"
    echo -e "${RED}Aborting: compose file is invalid${NC}"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 2: Build image
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[2/5] Building sks5 image...${NC}"
podman-compose build sks5
# podman-compose may not propagate exit codes; verify the image exists
IMAGE_NAME="sks5_sks5"
if podman image exists "$IMAGE_NAME" 2>/dev/null; then
    pass "Image built successfully"
else
    fail "Image build failed (image $IMAGE_NAME not found)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 3: Generate secrets
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[3/5] Generating test secrets...${NC}"
generate_secrets

# ---------------------------------------------------------------------------
# Step 4: Test Mode 1 — Config file (default service)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[4/5] Testing Mode 1 — Config file (service: sks5)...${NC}"

pc up -d sks5

# Find container name (podman-compose may prefix/suffix)
SKS5_CONTAINER=$(podman ps --format '{{.Names}}' | grep -E 'sks5[-_]sks5[-_]' | grep -v 'sks5-env\|sks5-tls' | head -1)

if [ -n "$SKS5_CONTAINER" ]; then
    # Try healthcheck first, fall back to running state check
    if wait_healthy "$SKS5_CONTAINER" 30 2>/dev/null || wait_running "$SKS5_CONTAINER" 15; then
        # Give the server a moment to bind the port
        sleep 2
        pass "Mode 1: container is up"
    else
        fail "Mode 1: container did not start"
        echo "  Container logs:"
        podman logs "$SKS5_CONTAINER" 2>&1 | tail -10
    fi

    # Test TCP connect on allocated port
    if command -v nc &>/dev/null; then
        if nc -z -w 3 127.0.0.1 "$PORT_SSH" 2>/dev/null; then
            pass "Mode 1: TCP connect to port $PORT_SSH (SSH)"
        else
            fail "Mode 1: TCP connect to port $PORT_SSH refused"
        fi
    else
        echo -e "${YELLOW}  SKIP: nc not available, skipping TCP connect test${NC}"
    fi
else
    fail "Mode 1: could not find sks5 container"
fi

pc down

# ---------------------------------------------------------------------------
# Step 5: Test Mode 2 — Env vars (profile: env, service: sks5-env)
# ---------------------------------------------------------------------------
echo -e "${YELLOW}[5/5] Testing Mode 2 — Env vars (service: sks5-env)...${NC}"

# podman-compose v1.0.6 doesn't support --profile; create a temp file
# with the profiles line removed so sks5-env is treated as a default service
TEMP_COMPOSE_ENV="${TEMP_COMPOSE%.yml}-env.yml"
sed '/profiles: \["env"\]/d' "$TEMP_COMPOSE" > "$TEMP_COMPOSE_ENV"

pc_env() {
    podman-compose -f "$TEMP_COMPOSE_ENV" "$@"
}

pc_env up -d sks5-env

# Find container name
SKS5_ENV_CONTAINER=$(podman ps --format '{{.Names}}' | grep 'sks5-env' | head -1)

if [ -n "$SKS5_ENV_CONTAINER" ]; then
    if wait_healthy "$SKS5_ENV_CONTAINER" 30 2>/dev/null || wait_running "$SKS5_ENV_CONTAINER" 15; then
        sleep 2
        pass "Mode 2: container is up"
    else
        fail "Mode 2: container did not start"
        echo "  Container logs:"
        podman logs "$SKS5_ENV_CONTAINER" 2>&1 | tail -10
    fi

    # Test SSH auth (if sshpass is available)
    if command -v sshpass &>/dev/null; then
        if sshpass -p alicetest ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p "$PORT_SSH" alice@127.0.0.1 whoami 2>/dev/null; then
            pass "Mode 2: SSH auth for alice"
        else
            fail "Mode 2: SSH auth for alice failed"
        fi
    else
        echo -e "${YELLOW}  SKIP: sshpass not available, skipping SSH auth test${NC}"
    fi

    # Test API health endpoint (if curl is available)
    if command -v curl &>/dev/null; then
        # Read API token from generated secrets
        API_TOKEN=$(cat "$SECRETS_DIR/api_token.txt" 2>/dev/null || echo "test-api-token-12345")
        API_OK=false
        for i in 1 2 3 4 5; do
            # Try with auth header first, then without (depends on server config)
            if curl -sf -H "Authorization: Bearer $API_TOKEN" "http://127.0.0.1:${PORT_API}/api/health" >/dev/null 2>&1 \
               || curl -sf "http://127.0.0.1:${PORT_API}/api/health" >/dev/null 2>&1; then
                API_OK=true
                break
            fi
            sleep 2
        done
        if [ "$API_OK" = true ]; then
            pass "Mode 2: API health endpoint responds"
        else
            fail "Mode 2: API health endpoint not reachable"
        fi
    else
        echo -e "${YELLOW}  SKIP: curl not available, skipping API health test${NC}"
    fi
else
    fail "Mode 2: could not find sks5-env container"
fi

pc_env down
rm -f "$TEMP_COMPOSE_ENV"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================="
TOTAL=$((PASSED + FAILED))
echo "  Results: $PASSED/$TOTAL passed"
if [ "$FAILED" -gt 0 ]; then
    echo -e "  ${RED}$FAILED test(s) FAILED${NC}"
    echo "========================================="
    exit 1
else
    echo -e "  ${GREEN}All tests passed!${NC}"
    echo "========================================="
    exit 0
fi
