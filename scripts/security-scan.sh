#!/bin/bash
# Security scanning script for sks5
# Runs cargo-audit, clippy, and cargo-deny (if available)

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

echo "========================================="
echo "  sks5 Security Scan"
echo "========================================="
echo ""

# 1. Clippy with all warnings as errors
echo -e "${YELLOW}[1/4] Running cargo clippy...${NC}"
if cargo clippy --all-targets -- -D warnings 2>&1; then
    echo -e "${GREEN}  ✓ Clippy passed${NC}"
else
    echo -e "${RED}  ✗ Clippy found issues${NC}"
    ERRORS=$((ERRORS + 1))
fi
echo ""

# 2. cargo-audit (vulnerability scan)
echo -e "${YELLOW}[2/4] Running cargo audit...${NC}"
if command -v cargo-audit &>/dev/null; then
    if cargo audit 2>&1; then
        echo -e "${GREEN}  ✓ No known vulnerabilities${NC}"
    else
        echo -e "${RED}  ✗ Vulnerabilities found${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}  ⚠ cargo-audit not installed (install with: cargo install cargo-audit)${NC}"
fi
echo ""

# 3. cargo-deny (license + advisory check)
echo -e "${YELLOW}[3/4] Running cargo deny...${NC}"
if command -v cargo-deny &>/dev/null; then
    if cargo deny check 2>&1; then
        echo -e "${GREEN}  ✓ cargo-deny passed${NC}"
    else
        echo -e "${RED}  ✗ cargo-deny found issues${NC}"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${YELLOW}  ⚠ cargo-deny not installed (install with: cargo install cargo-deny)${NC}"
fi
echo ""

# 4. Docker image vulnerability scan (optional)
echo -e "${YELLOW}[4/4] Docker image scan (Trivy)...${NC}"
if command -v trivy &>/dev/null; then
    if podman image exists sks5:latest 2>/dev/null; then
        if trivy image --image-src podman --exit-code 1 --severity CRITICAL,HIGH sks5:latest 2>&1; then
            echo -e "${GREEN}  ok Trivy passed (alpine)${NC}"
        else
            echo -e "${RED}  !! Trivy found vulnerabilities (alpine)${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}  -- sks5:latest not built (skipped)${NC}"
    fi
    if podman image exists sks5:scratch 2>/dev/null; then
        if trivy image --image-src podman --exit-code 1 --severity CRITICAL,HIGH sks5:scratch 2>&1; then
            echo -e "${GREEN}  ok Trivy passed (scratch)${NC}"
        else
            echo -e "${RED}  !! Trivy found vulnerabilities (scratch)${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}  -- sks5:scratch not built (skipped)${NC}"
    fi
else
    echo -e "${YELLOW}  -- trivy not installed (install: https://trivy.dev)${NC}"
fi
echo ""

# Summary
echo "========================================="
if [ "$ERRORS" -eq 0 ]; then
    echo -e "${GREEN}  All checks passed!${NC}"
    exit 0
else
    echo -e "${RED}  $ERRORS check(s) failed${NC}"
    exit 1
fi
