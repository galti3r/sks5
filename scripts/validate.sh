#!/usr/bin/env bash
# sks5 Comprehensive Validation Script
# Parallelized 4-phase validation with dynamic test discovery
# Usage: ./scripts/validate.sh [--skip-browser] [--skip-coverage] [--skip-act] [--dry-run]
set -uo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
TOTAL_START=$SECONDS

# CLI flags
SKIP_BROWSER=false
SKIP_COVERAGE=false
SKIP_ACT=false
WITH_DOCKER=false
DRY_RUN=false

for arg in "$@"; do
    case "$arg" in
        --skip-browser)  SKIP_BROWSER=true ;;
        --skip-coverage) SKIP_COVERAGE=true ;;
        --skip-act)      SKIP_ACT=true ;;
        --with-docker)   WITH_DOCKER=true ;;
        --dry-run)       DRY_RUN=true ;;
        --help|-h)
            echo "Usage: $0 [--skip-browser] [--skip-coverage] [--skip-act] [--with-docker] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --skip-browser   Skip browser E2E tests (requires Podman + Chrome)"
            echo "  --skip-coverage  Skip code coverage generation"
            echo "  --skip-act       Skip act-based CI jobs even if act is available"
            echo "  --with-docker    Include Docker image build verification (requires Podman)"
            echo "  --dry-run        Show what would be executed without running"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use --help for usage)"
            exit 1
            ;;
    esac
done

# Tool availability (set by detect_tools)
ACT_AVAILABLE=false
PODMAN_AVAILABLE=false
LLVM_COV_AVAILABLE=false
MSRV_AVAILABLE=false
VHS_AVAILABLE=false
AUDIT_AVAILABLE=false
DENY_AVAILABLE=false

# Error tracking
declare -a ERRORS=()
JOB_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# ---------------------------------------------------------------------------
# Colors & formatting
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' NC=''
fi

log_header() {
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""
}

log_phase() {
    echo ""
    echo -e "${BLUE}${BOLD}[$1]${NC} ${BOLD}$2${NC}"
}

log_start() {
    echo -e "  ${DIM}>${NC} $1"
}

log_success() {
    local duration="${2:-}"
    if [[ -n "$duration" ]]; then
        printf "  ${GREEN}%-2s${NC} %-38s ${DIM}%s${NC}\n" "ok" "$1" "${duration}s"
    else
        echo -e "  ${GREEN}ok${NC} $1"
    fi
}

log_failure() {
    local duration="${2:-}"
    if [[ -n "$duration" ]]; then
        printf "  ${RED}%-2s${NC} %-38s ${DIM}%s${NC}\n" "!!" "$1" "${duration}s"
    else
        echo -e "  ${RED}!!${NC} $1"
    fi
}

log_skip() {
    echo -e "  ${YELLOW}--${NC} $1 ${DIM}(skipped)${NC}"
}

log_warning() {
    echo -e "  ${YELLOW}!!${NC} $1"
}

# ---------------------------------------------------------------------------
# run_job "name" command...
# Synchronous: runs a command, captures output and result in TMP_DIR files.
# Use with & at call site for parallel execution, without & for sequential.
# ---------------------------------------------------------------------------
run_job() {
    local name="$1"
    shift
    local safe_name
    safe_name=$(echo "$name" | sed 's/[^a-zA-Z0-9._-]/_/g')

    # Store original name for display
    echo "$name" > "$TMP_DIR/name.$safe_name"

    if $DRY_RUN; then
        log_start "$name: $*"
        echo "0" > "$TMP_DIR/result.$safe_name"
        echo "0" > "$TMP_DIR/time.$safe_name"
        return 0
    fi

    log_start "$name"
    local job_start=$SECONDS
    if "$@" > "$TMP_DIR/log.$safe_name" 2>&1; then
        echo "0" > "$TMP_DIR/result.$safe_name"
    else
        echo "1" > "$TMP_DIR/result.$safe_name"
    fi
    echo "$(( SECONDS - job_start ))" > "$TMP_DIR/time.$safe_name"
}

# ---------------------------------------------------------------------------
# wait_phase "Phase N: Description"
# Waits for all background jobs, collects results, reports
# ---------------------------------------------------------------------------
wait_phase() {
    local phase_name="$1"
    wait

    local has_failures=false
    for result_file in "$TMP_DIR"/result.*; do
        [[ -f "$result_file" ]] || continue
        local safe_name="${result_file##*/result.}"
        local job_name="$safe_name"
        if [[ -f "$TMP_DIR/name.$safe_name" ]]; then
            job_name=$(cat "$TMP_DIR/name.$safe_name")
        fi
        local status
        status=$(cat "$result_file")
        local duration="?"
        if [[ -f "$TMP_DIR/time.$safe_name" ]]; then
            duration=$(cat "$TMP_DIR/time.$safe_name")
        fi

        JOB_COUNT=$(( JOB_COUNT + 1 ))
        if [[ "$status" == "0" ]]; then
            log_success "$job_name" "$duration"
            PASS_COUNT=$(( PASS_COUNT + 1 ))
        else
            log_failure "$job_name" "$duration"
            ERRORS+=("$phase_name > $job_name")
            FAIL_COUNT=$(( FAIL_COUNT + 1 ))
            has_failures=true
        fi
    done

    # Clean up result/time/name files for next phase
    rm -f "$TMP_DIR"/result.* "$TMP_DIR"/time.* "$TMP_DIR"/name.*

    if $has_failures; then
        echo ""
        log_warning "Some jobs failed in $phase_name (continuing...)"
    fi
}

# ---------------------------------------------------------------------------
# show_job_log "name"
# Shows the log for a failed job
# ---------------------------------------------------------------------------
show_job_log() {
    local name="$1"
    local safe_name
    safe_name=$(echo "$name" | sed 's/[^a-zA-Z0-9._-]/_/g')
    local log_file="$TMP_DIR/log.$safe_name"
    if [[ -f "$log_file" ]] && [[ -s "$log_file" ]]; then
        echo ""
        echo -e "${DIM}--- Output: $name ---${NC}"
        tail -30 "$log_file"
        echo -e "${DIM}--- End ---${NC}"
    fi
}

# ---------------------------------------------------------------------------
# detect_tools — check which tools are available
# ---------------------------------------------------------------------------
detect_tools() {
    if ! $SKIP_ACT && command -v act &>/dev/null; then
        ACT_AVAILABLE=true
    fi
    if command -v podman &>/dev/null; then
        PODMAN_AVAILABLE=true
    fi
    if command -v cargo-llvm-cov &>/dev/null; then
        LLVM_COV_AVAILABLE=true
    fi
    if rustup toolchain list 2>/dev/null | grep -q '^1\.88'; then
        MSRV_AVAILABLE=true
    fi
    if command -v vhs &>/dev/null; then
        VHS_AVAILABLE=true
    fi
    if command -v cargo-audit &>/dev/null; then
        AUDIT_AVAILABLE=true
    fi
    if command -v cargo-deny &>/dev/null; then
        DENY_AVAILABLE=true
    fi

    echo -e "${CYAN}[Tools]${NC} " \
        "$(bool_icon $ACT_AVAILABLE) act " \
        "$(bool_icon $PODMAN_AVAILABLE) podman " \
        "$(bool_icon $LLVM_COV_AVAILABLE) llvm-cov " \
        "$(bool_icon $MSRV_AVAILABLE) MSRV 1.88 " \
        "$(bool_icon $AUDIT_AVAILABLE) audit " \
        "$(bool_icon $DENY_AVAILABLE) deny " \
        "$(bool_icon $VHS_AVAILABLE) vhs"
}

bool_icon() {
    if $1; then echo -e "${GREEN}ok${NC}"; else echo -e "${DIM}--${NC}"; fi
}

# ---------------------------------------------------------------------------
# auto_install — install missing tools that can be installed locally
# ---------------------------------------------------------------------------
auto_install() {
    if ! $SKIP_COVERAGE && ! $LLVM_COV_AVAILABLE; then
        echo -e "  ${YELLOW}Installing llvm-tools-preview...${NC}"
        if ! $DRY_RUN; then
            rustup component add llvm-tools-preview 2>/dev/null || true
        fi

        echo -e "  ${YELLOW}Installing cargo-llvm-cov...${NC}"
        if ! $DRY_RUN; then
            if cargo install cargo-llvm-cov --locked 2>/dev/null; then
                LLVM_COV_AVAILABLE=true
            fi
        fi
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# cleanup_act_containers — remove stale act containers from previous runs
# ---------------------------------------------------------------------------
cleanup_act_containers() {
    if $PODMAN_AVAILABLE; then
        local stale
        stale=$(podman ps -aq --filter "name=act-" 2>/dev/null || true)
        if [[ -n "$stale" ]]; then
            echo -e "  ${DIM}Cleaning stale act containers...${NC}"
            echo "$stale" | xargs -r podman rm -f 2>/dev/null || true
        fi
    fi
}

# ---------------------------------------------------------------------------
# discover_e2e_tests — parse Cargo.toml for [[test]] entries starting with e2e_
# Excludes e2e_browser_* (handled separately in Phase 4)
# ---------------------------------------------------------------------------
discover_e2e_tests() {
    sed -n '/^\[\[test\]\]/,/^$/p' "$PROJECT_ROOT/Cargo.toml" | \
        grep '^name' | sed 's/.*"\(.*\)"/\1/' | \
        grep '^e2e_' | grep -v '^e2e_browser'
}

# ---------------------------------------------------------------------------
# classify_test — assign a test to a parallel group
# ---------------------------------------------------------------------------
classify_test() {
    local test="$1"
    case "$test" in
        e2e_auth|e2e_ssh*|e2e_socks5*|e2e_forwarding|e2e_rejection)
            echo "ssh_socks5" ;;
        e2e_acl*|e2e_autoban|e2e_shell*|e2e_upstream*)
            echo "acl_security" ;;
        e2e_api*|e2e_quota*|e2e_status|e2e_cli)
            echo "api_dashboard" ;;
        e2e_audit*|e2e_webhook*|e2e_sse*|e2e_ws|e2e_metrics*|e2e_backup*|e2e_reload|e2e_performance)
            echo "integrations" ;;
        *)
            echo "catchall" ;;
    esac
}

# ---------------------------------------------------------------------------
# Phase 1: Lint + Security (parallel)
# ---------------------------------------------------------------------------
phase1() {
    log_phase "Phase 1" "Lint + Security"

    if $ACT_AVAILABLE; then
        cleanup_act_containers
        # Act jobs run sequentially (shared container names) but parallel with other Phase 1 jobs
        run_job "CI Lint (act)" bash -c 'make ci-lint && make ci-docker-lint' &
    else
        run_job "Format check" cargo fmt --all -- --check &
    fi

    if $AUDIT_AVAILABLE; then
        run_job "Security: audit" cargo audit &
    else
        log_skip "cargo audit (not installed)"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $DENY_AVAILABLE; then
        run_job "Security: deny" cargo deny check &
    else
        log_skip "cargo deny (not installed)"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $MSRV_AVAILABLE; then
        run_job "MSRV (1.88)" cargo +1.88 check &
    else
        log_skip "MSRV check (toolchain 1.88 not installed)"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    wait_phase "Phase 1: Lint + Security"
}

# ---------------------------------------------------------------------------
# Phase 2: Compilation (sequential — builds the cache for Phase 3)
# ---------------------------------------------------------------------------
phase2() {
    log_phase "Phase 2" "Compilation"

    if ! $ACT_AVAILABLE; then
        run_job "Clippy" cargo clippy --all-targets -- -D warnings
    fi

    run_job "Compile tests" cargo test --all-targets --no-run

    # Collect all Phase 2 results (no bg jobs, but reuse wait_phase for reporting)
    wait_phase "Phase 2: Compilation"
}

# ---------------------------------------------------------------------------
# Phase 3: Tests in parallel groups (dynamically discovered)
# ---------------------------------------------------------------------------
phase3() {
    log_phase "Phase 3" "Tests (parallel groups)"

    # Discover and classify E2E tests
    declare -A TEST_GROUPS
    declare -A GROUP_LABELS
    GROUP_LABELS=(
        [ssh_socks5]="SSH & SOCKS5"
        [acl_security]="ACL & Security"
        [api_dashboard]="API & Dashboard"
        [integrations]="Integrations"
        [catchall]="Catchall"
    )

    while IFS= read -r test; do
        local group
        group=$(classify_test "$test")
        TEST_GROUPS[$group]+=" --test $test"
    done < <(discover_e2e_tests)

    # Show discovered groups
    local discovered_count=0
    for group in ssh_socks5 acl_security api_dashboard integrations catchall; do
        if [[ -n "${TEST_GROUPS[$group]:-}" ]]; then
            local tests="${TEST_GROUPS[$group]}"
            local count
            count=$(echo "$tests" | tr ' ' '\n' | grep -c '^--test$' || true)
            echo -e "  ${DIM}${GROUP_LABELS[$group]}: ${count} tests${NC}"
            discovered_count=$(( discovered_count + count ))
        fi
    done
    echo -e "  ${DIM}Total discovered: ${discovered_count} E2E tests${NC}"
    echo ""

    # Launch unit tests
    run_job "Unit tests" cargo test --lib --test unit &

    # Launch E2E test groups
    for group in ssh_socks5 acl_security api_dashboard integrations catchall; do
        if [[ -n "${TEST_GROUPS[$group]:-}" ]]; then
            # Build the cargo test command with all --test flags
            local args="${TEST_GROUPS[$group]}"
            # shellcheck disable=SC2086
            run_job "E2E: ${GROUP_LABELS[$group]}" cargo test $args &
        fi
    done

    wait_phase "Phase 3: Tests"
}

# ---------------------------------------------------------------------------
# Phase 4: Extras (coverage, browser, vhs) — parallel
# ---------------------------------------------------------------------------
phase4() {
    log_phase "Phase 4" "Coverage + Browser + Extras"

    local has_jobs=false

    if ! $SKIP_COVERAGE && $LLVM_COV_AVAILABLE; then
        run_job "Coverage" cargo llvm-cov --lcov --output-path lcov.info --lib --test unit &
        has_jobs=true
    else
        if $SKIP_COVERAGE; then
            log_skip "Coverage (--skip-coverage)"
        else
            log_skip "Coverage (cargo-llvm-cov not available)"
        fi
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if ! $SKIP_BROWSER && $PODMAN_AVAILABLE; then
        run_job "E2E Browser" make test-e2e-browser &
        has_jobs=true
    else
        if $SKIP_BROWSER; then
            log_skip "E2E Browser (--skip-browser)"
        else
            log_skip "E2E Browser (podman not available)"
        fi
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $WITH_DOCKER && $PODMAN_AVAILABLE; then
        run_job "Docker Build" make docker-build &
        has_jobs=true
    elif $WITH_DOCKER; then
        log_skip "Docker Build (podman not available)"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $VHS_AVAILABLE; then
        if [[ -f "$PROJECT_ROOT/contrib/demo.tape" ]]; then
            run_job "VHS Demo" vhs "$PROJECT_ROOT/contrib/demo.tape" &
            has_jobs=true
        else
            log_skip "VHS Demo (contrib/demo.tape not found)"
            SKIP_COUNT=$(( SKIP_COUNT + 1 ))
        fi
    else
        log_skip "VHS Demo (vhs not installed)"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $has_jobs; then
        wait_phase "Phase 4: Extras"
    fi
}

# ---------------------------------------------------------------------------
# summary — final report
# ---------------------------------------------------------------------------
summary() {
    local total_time=$(( SECONDS - TOTAL_START ))
    local minutes=$(( total_time / 60 ))
    local seconds=$(( total_time % 60 ))
    local time_str
    if (( minutes > 0 )); then
        time_str="${minutes}m ${seconds}s"
    else
        time_str="${seconds}s"
    fi

    echo ""
    echo -e "${BOLD}=========================================${NC}"
    if [[ ${#ERRORS[@]} -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  ok All ${JOB_COUNT} checks passed (${time_str})${NC}"
        if (( SKIP_COUNT > 0 )); then
            echo -e "${DIM}  (${SKIP_COUNT} skipped)${NC}"
        fi
    else
        echo -e "${RED}${BOLD}  !! ${FAIL_COUNT}/${JOB_COUNT} checks failed (${time_str})${NC}"
        if (( SKIP_COUNT > 0 )); then
            echo -e "${DIM}  (${SKIP_COUNT} skipped)${NC}"
        fi
        echo ""
        echo -e "${RED}  Failures:${NC}"
        for err in "${ERRORS[@]}"; do
            echo -e "  ${RED}!!${NC} $err"
        done

        # Show logs for failed jobs
        for err in "${ERRORS[@]}"; do
            local job_name="${err##*> }"
            show_job_log "$job_name"
        done
    fi
    echo -e "${BOLD}=========================================${NC}"
    echo ""

    if [[ ${#ERRORS[@]} -gt 0 ]]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    log_header "sks5 Comprehensive Validation"

    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY RUN] Showing planned execution without running commands${NC}"
        echo ""
    fi

    detect_tools
    auto_install

    phase1
    phase2
    phase3
    phase4
    summary
}

main "$@"
