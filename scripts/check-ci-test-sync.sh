#!/bin/sh
# check-ci-test-sync.sh — Verify E2E tests in Cargo.toml match ci.yml matrix
# Exit 1 if any test in Cargo.toml is missing from ci.yml (or vice versa).
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR/.."

CARGO_TOML="$PROJECT_ROOT/Cargo.toml"
CI_YML="$PROJECT_ROOT/.github/workflows/ci.yml"

TMP_CARGO=$(mktemp)
TMP_CI=$(mktemp)
trap 'rm -f "$TMP_CARGO" "$TMP_CI"' EXIT

# 1. Extract E2E test names from Cargo.toml (same logic as discover_e2e_tests)
sed -n '/^\[\[test\]\]/,/^$/p' "$CARGO_TOML" | \
    grep '^name' | sed 's/.*"\(.*\)"/\1/' | \
    grep '^e2e_' | grep -v '^e2e_browser' | sort > "$TMP_CARGO"

# 2. Extract E2E test names from ci.yml matrix (exclude browser tests, same as above)
grep -o '\-\-test e2e_[^ "]*' "$CI_YML" | sed 's/--test //' | \
    grep -v '^e2e_browser' | sort -u > "$TMP_CI"

# 3. Compare
missing_from_ci=$(comm -23 "$TMP_CARGO" "$TMP_CI")
missing_from_cargo=$(comm -13 "$TMP_CARGO" "$TMP_CI")

rc=0

if [ -n "$missing_from_ci" ]; then
    echo "ERROR: E2E tests in Cargo.toml but NOT in ci.yml matrix:"
    echo "$missing_from_ci" | while IFS= read -r t; do
        echo "  - $t"
    done
    echo ""
    echo "Add these tests to .github/workflows/ci.yml e2e-tests matrix."
    rc=1
fi

if [ -n "$missing_from_cargo" ]; then
    echo "WARNING: E2E tests in ci.yml but NOT in Cargo.toml:"
    echo "$missing_from_cargo" | while IFS= read -r t; do
        echo "  - $t"
    done
    echo ""
    echo "Remove stale entries from .github/workflows/ci.yml e2e-tests matrix."
    rc=1
fi

if [ $rc -eq 0 ]; then
    count=$(wc -l < "$TMP_CARGO" | tr -d ' ')
    echo "OK: $count E2E tests in sync between Cargo.toml and ci.yml"
fi

exit $rc
