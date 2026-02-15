#!/bin/bash
# E2E tests executed from inside the test client container
# Usage: run-e2e-in-container.sh <server_host> <port> <username> <password>

set -euo pipefail

SERVER="${1:-sks5-server}"
PORT="${2:-2222}"
USER="${3:-testuser}"
PASS="${4:-testpass}"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

TESTS=0
PASSED=0
FAILED=0

run_test() {
    local name="$1"
    shift
    TESTS=$((TESTS + 1))
    echo -n "  [$TESTS] $name ... "
    if "$@" 2>/dev/null; then
        echo -e "${GREEN}PASS${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAILED=$((FAILED + 1))
    fi
}

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -p $PORT"

echo "Running E2E tests against $SERVER:$PORT"
echo "========================================="

# Test 1: Password auth works
run_test "Password auth" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER whoami | grep -q '$USER'"

# Test 2: Wrong password rejected
run_test "Wrong password rejected" bash -c \
    "! sshpass -p 'wrongpass' ssh $SSH_OPTS $USER@$SERVER whoami 2>/dev/null"

# Test 3: whoami returns username
run_test "whoami command" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER whoami | grep -q '$USER'"

# Test 4: hostname returns configured value
run_test "hostname command" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER hostname | grep -q 'sks5'"

# Test 5: echo works
run_test "echo command" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER 'echo hello123' | grep -q 'hello123'"

# Test 6: id returns uid info
run_test "id command" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER id | grep -q 'uid='"

# Test 7: env shows USER
run_test "env command" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER env | grep -q 'USER=$USER'"

# Test 8: help lists commands
run_test "help command" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER help | grep -q 'ls'"

# Test 9: bash blocked
run_test "bash blocked" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER bash 2>&1 | grep -q 'command not found'"

# Test 10: wget blocked
run_test "wget blocked" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER 'wget http://example.com' 2>&1 | grep -q 'command not found'"

# Test 11: python blocked
run_test "python blocked" bash -c \
    "sshpass -p '$PASS' ssh $SSH_OPTS $USER@$SERVER python 2>&1 | grep -q 'command not found'"

# Test 12: SFTP rejected
run_test "SFTP rejected" bash -c \
    "! sshpass -p '$PASS' sftp -P $PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $USER@$SERVER <<< 'ls' 2>/dev/null"

# Test 13: Reverse forwarding rejected
run_test "Reverse forward rejected" bash -c \
    "timeout 5 sshpass -p '$PASS' ssh $SSH_OPTS -R 0:localhost:22 -N $USER@$SERVER 2>&1; [ \$? -ne 0 ]"

echo ""
echo "========================================="
echo "Results: $PASSED/$TESTS passed, $FAILED failed"
echo "========================================="

[ "$FAILED" -eq 0 ]
