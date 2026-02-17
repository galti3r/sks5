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
DOCKER_AVAILABLE=false
LLVM_COV_AVAILABLE=false
MSRV_AVAILABLE=false
VHS_AVAILABLE=false
VHS_VIA=""       # "native" | "podman" | "docker"
AUDIT_AVAILABLE=false
DENY_AVAILABLE=false
TRIVY_AVAILABLE=false
TRIVY_VIA=""     # "native" | "podman" | "docker"

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
    if command -v docker &>/dev/null; then
        DOCKER_AVAILABLE=true
    fi
    if command -v cargo-llvm-cov &>/dev/null; then
        LLVM_COV_AVAILABLE=true
    fi
    if rustup toolchain list 2>/dev/null | grep -q '^1\.88'; then
        MSRV_AVAILABLE=true
    fi
    if command -v cargo-audit &>/dev/null; then
        AUDIT_AVAILABLE=true
    fi
    if command -v cargo-deny &>/dev/null; then
        DENY_AVAILABLE=true
    fi

    # trivy: native → podman → docker
    if command -v trivy &>/dev/null; then
        TRIVY_AVAILABLE=true; TRIVY_VIA="native"
    elif $PODMAN_AVAILABLE; then
        TRIVY_AVAILABLE=true; TRIVY_VIA="podman"
    elif $DOCKER_AVAILABLE; then
        TRIVY_AVAILABLE=true; TRIVY_VIA="docker"
    fi

    # vhs: native → podman → docker
    if command -v vhs &>/dev/null; then
        VHS_AVAILABLE=true; VHS_VIA="native"
    elif $PODMAN_AVAILABLE; then
        VHS_AVAILABLE=true; VHS_VIA="podman"
    elif $DOCKER_AVAILABLE; then
        VHS_AVAILABLE=true; VHS_VIA="docker"
    fi

    echo -e "${CYAN}[Tools]${NC} " \
        "$(tool_label $ACT_AVAILABLE act) " \
        "$(tool_label $PODMAN_AVAILABLE podman) " \
        "$(tool_label $LLVM_COV_AVAILABLE llvm-cov) " \
        "$(tool_label $MSRV_AVAILABLE 'MSRV 1.88') " \
        "$(tool_label $AUDIT_AVAILABLE audit) " \
        "$(tool_label $DENY_AVAILABLE deny) " \
        "$(tool_label_via $TRIVY_AVAILABLE trivy "$TRIVY_VIA") " \
        "$(tool_label_via $VHS_AVAILABLE vhs "$VHS_VIA")"
}

# ---------------------------------------------------------------------------
# Container-fallback commands for trivy and vhs
# ---------------------------------------------------------------------------
trivy_command() {
    case "$TRIVY_VIA" in
        native) echo "trivy" ;;
        podman) echo "podman run --rm -v ${XDG_RUNTIME_DIR}/podman/podman.sock:/var/run/docker.sock:ro ghcr.io/aquasecurity/trivy:latest" ;;
        docker) echo "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro ghcr.io/aquasecurity/trivy:latest" ;;
    esac
}

# When trivy runs inside a container, the podman socket is mounted as
# /var/run/docker.sock, so trivy must use the Docker API (--image-src docker).
trivy_image_src() {
    case "$TRIVY_VIA" in
        native) echo "podman" ;;
        podman|docker) echo "docker" ;;
    esac
}

vhs_command() {
    case "$VHS_VIA" in
        native) echo "vhs" ;;
        podman) echo "podman run --rm -v ${PWD}:/vhs ghcr.io/charmbracelet/vhs" ;;
        docker) echo "docker run --rm -v ${PWD}:/vhs ghcr.io/charmbracelet/vhs" ;;
    esac
}

# Display "ok name" or "-- name"
tool_label() {
    if $1; then echo -e "${GREEN}ok${NC} $2"; else echo -e "${DIM}--${NC} ${DIM}$2${NC}"; fi
}

# Display "ok name" or "ok name (podman)" or "-- name"
tool_label_via() {
    local available="$1" name="$2" via="$3"
    if $available; then
        if [[ "$via" == "native" ]]; then
            echo -e "${GREEN}ok${NC} $name"
        else
            echo -e "${GREEN}ok${NC} $name ${DIM}($via)${NC}"
        fi
    else
        echo -e "${DIM}--${NC} ${DIM}$name${NC}"
    fi
}

plan_run() {
    printf "  ${GREEN}%-3s${NC} %-40s %s\n" "RUN" "$1" "${2:-}"
}
plan_not() {
    printf "  ${YELLOW}%-3s${NC} %-40s ${DIM}%s${NC}\n" "---" "$1" "$2"
}
plan_phase() {
    echo -e "  ${BLUE}${BOLD}$1${NC}"
}

# ---------------------------------------------------------------------------
# show_plan — display a summary of what will run and what won't
# ---------------------------------------------------------------------------
show_plan() {
    local -a not_covered=()
    local run_count=0

    echo ""
    echo -e "${BOLD}  Will run${NC}"
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"

    # Phase 1
    plan_phase "Phase 1: Lint + Security"
    if $ACT_AVAILABLE; then
        plan_run "CI Lint + Docker Lint (act)"
    else
        plan_run "Format check"
    fi
    run_count=$(( run_count + 1 ))
    if $AUDIT_AVAILABLE; then plan_run "Security: audit"; run_count=$(( run_count + 1 )); else not_covered+=("Security: audit"); fi
    if $DENY_AVAILABLE; then plan_run "Security: deny"; run_count=$(( run_count + 1 )); else not_covered+=("Security: deny"); fi
    if $MSRV_AVAILABLE; then plan_run "MSRV (1.88)"; run_count=$(( run_count + 1 )); else not_covered+=("MSRV (1.88)"); fi

    # Phase 2
    plan_phase "Phase 2: Compilation"
    if ! $ACT_AVAILABLE; then plan_run "Clippy"; run_count=$(( run_count + 1 )); fi
    plan_run "Compile tests"
    run_count=$(( run_count + 1 ))

    # Phase 3
    plan_phase "Phase 3: Tests"
    plan_run "Unit tests"
    run_count=$(( run_count + 1 ))
    declare -A PLAN_GROUPS
    while IFS= read -r test; do
        local group
        group=$(classify_test "$test")
        PLAN_GROUPS[$group]=$(( ${PLAN_GROUPS[$group]:-0} + 1 ))
    done < <(discover_e2e_tests)
    declare -A PLAN_LABELS=([ssh_socks5]="SSH & SOCKS5" [acl_security]="ACL & Security" [api_dashboard]="API & Dashboard" [integrations]="Integrations" [catchall]="Catchall")
    for group in ssh_socks5 acl_security api_dashboard integrations catchall; do
        local count="${PLAN_GROUPS[$group]:-0}"
        if (( count > 0 )); then
            plan_run "E2E: ${PLAN_LABELS[$group]}" "${count} tests"
            run_count=$(( run_count + 1 ))
        fi
    done

    # Phase 4
    plan_phase "Phase 4: Coverage + Browser + Extras"
    if ! $SKIP_COVERAGE && $LLVM_COV_AVAILABLE; then
        plan_run "Coverage (llvm-cov)"; run_count=$(( run_count + 1 ))
    else
        not_covered+=("Coverage")
    fi
    if ! $SKIP_BROWSER && $PODMAN_AVAILABLE; then
        plan_run "E2E Browser + Screenshots"; run_count=$(( run_count + 1 ))
    else
        not_covered+=("E2E Browser + Screenshots")
    fi
    if $WITH_DOCKER && $PODMAN_AVAILABLE; then
        if $TRIVY_AVAILABLE; then
            local trivy_label="Docker Build + Scan"
            [[ "$TRIVY_VIA" != "native" ]] && trivy_label="Docker Build + Scan (trivy via $TRIVY_VIA)"
            plan_run "$trivy_label"; run_count=$(( run_count + 1 ))
        else
            plan_run "Docker Build"; run_count=$(( run_count + 1 ))
            not_covered+=("Docker Scan")
        fi
    elif ! $WITH_DOCKER; then
        not_covered+=("Docker Build + Scan      -> use: make validate-docker")
    fi
    if $VHS_AVAILABLE; then
        local tape_count=0
        for tape in "$PROJECT_ROOT"/contrib/*.tape; do [[ -f "$tape" ]] && tape_count=$(( tape_count + 1 )); done
        if (( tape_count > 0 )); then
            local vhs_label="VHS"
            [[ "$VHS_VIA" != "native" ]] && vhs_label="VHS (via $VHS_VIA)"
            plan_run "$vhs_label" "${tape_count} tapes"; run_count=$(( run_count + 1 ))
        fi
    else
        not_covered+=("VHS recordings")
    fi

    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"

    # Not covered section
    if (( ${#not_covered[@]} > 0 )); then
        echo ""
        echo -e "${BOLD}  Not covered${NC}"
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        for entry in "${not_covered[@]}"; do
            echo -e "  ${YELLOW}---${NC} ${entry}"
        done
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        # Show make setup hint only for missing tools (not for --with-docker hint)
        local has_missing_tools=false
        for entry in "${not_covered[@]}"; do
            [[ "$entry" != *"-> use:"* ]] && has_missing_tools=true && break
        done
        if $has_missing_tools; then
            echo -e "  ${YELLOW}Fix: ${BOLD}make setup${NC}${YELLOW} (auto-installs or creates podman/docker wrappers)${NC}"
        fi
    fi
    echo ""
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
        # Run browser + screenshots sequentially in one job to avoid
        # Chrome container cleanup race (both use --filter "name=sks5-chrome")
        run_job "E2E Browser + Screenshots" bash -c 'make test-e2e-browser && make test-screenshots' &
        has_jobs=true
    else
        if $SKIP_BROWSER; then
            log_skip "E2E Browser + Screenshots (--skip-browser)"
        else
            log_skip "E2E Browser + Screenshots (podman not available)"
        fi
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $WITH_DOCKER && $PODMAN_AVAILABLE; then
        if $TRIVY_AVAILABLE; then
            local trivy_cmd trivy_src
            trivy_cmd=$(trivy_command)
            trivy_src=$(trivy_image_src)
            run_job "Docker Build + Scan ($TRIVY_VIA)" bash -c \
                "make docker-build-all && $trivy_cmd image --image-src $trivy_src --exit-code 1 --severity CRITICAL,HIGH,MEDIUM sks5:latest && $trivy_cmd image --image-src $trivy_src --exit-code 1 --severity CRITICAL,HIGH,MEDIUM sks5:scratch" &
        else
            run_job "Docker Build" make docker-build-all &
            log_skip "Docker Scan (trivy not available)"
            SKIP_COUNT=$(( SKIP_COUNT + 1 ))
        fi
        has_jobs=true
    elif $WITH_DOCKER; then
        log_skip "Docker Build (podman not available)"
        SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    fi

    if $VHS_AVAILABLE; then
        local vhs_cmd
        vhs_cmd=$(vhs_command)
        local tape_count=0
        for tape in "$PROJECT_ROOT"/contrib/*.tape; do
            if [[ -f "$tape" ]]; then
                local tape_name tape_path
                tape_name=$(basename "$tape" .tape)
                # Container VHS mounts $PWD:/vhs — pass relative path
                if [[ "$VHS_VIA" == "native" ]]; then
                    tape_path="$tape"
                else
                    tape_path="${tape#"$PROJECT_ROOT"/}"
                fi
                run_job "VHS: $tape_name ($VHS_VIA)" $vhs_cmd "$tape_path" &
                has_jobs=true
                tape_count=$(( tape_count + 1 ))
            fi
        done
        if [[ $tape_count -eq 0 ]]; then
            log_skip "VHS (no .tape files in contrib/)"
            SKIP_COUNT=$(( SKIP_COUNT + 1 ))
        fi
    else
        log_skip "VHS (vhs not installed)"
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
    show_plan
    auto_install

    phase1
    phase2
    phase3
    phase4
    summary
}

main "$@"
