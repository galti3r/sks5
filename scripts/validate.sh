#!/usr/bin/env bash
# sks5 Comprehensive Validation Script v2
# Lane-parallel validation with fail-fast, live dashboard, and Gantt summary
# Usage: ./scripts/validate.sh [--skip-browser] [--skip-coverage] [--skip-act]
#                               [--with-docker] [--plain] [--dry-run]
set -uo pipefail

# ===========================================================================
# Configuration
# ===========================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"
export CARGO_INCREMENTAL=0

TMP_DIR=$(mktemp -d)
TOTAL_START=$SECONDS

# CLI flags
SKIP_BROWSER=false
SKIP_COVERAGE=false
SKIP_ACT=false
WITH_DOCKER=false
DRY_RUN=false
FORCE_PLAIN=false

for arg in "$@"; do
    case "$arg" in
        --skip-browser)  SKIP_BROWSER=true ;;
        --skip-coverage) SKIP_COVERAGE=true ;;
        --skip-act)      SKIP_ACT=true ;;
        --with-docker)   WITH_DOCKER=true ;;
        --plain)         FORCE_PLAIN=true ;;
        --dry-run)       DRY_RUN=true ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-browser   Skip browser E2E tests (requires Podman + Chrome)"
            echo "  --skip-coverage  Skip code coverage generation"
            echo "  --skip-act       Skip act-based CI jobs even if act is available"
            echo "  --with-docker    Include Docker image build + security scan"
            echo "  --plain          Force plain output (no live dashboard)"
            echo "  --dry-run        Show planned execution without running"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use --help for usage)"
            exit 1
            ;;
    esac
done

# Auto-detect display mode: pretty if TTY, plain otherwise
PRETTY_MODE=true
if $FORCE_PLAIN || ! [[ -t 1 ]]; then
    PRETTY_MODE=false
fi

# ===========================================================================
# Colors & Symbols
# ===========================================================================
if [[ -t 1 ]] && ! $FORCE_PLAIN; then
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

SPINNER=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
SPIN_IDX=0
SYM_OK="${GREEN}✓${NC}"
SYM_FAIL="${RED}✗${NC}"
SYM_WAIT="${DIM}○${NC}"
SYM_SKIP="${YELLOW}--${NC}"
SYM_KILL="${DIM}○${NC}"

get_spinner() {
    printf '%s' "${CYAN}${SPINNER[$SPIN_IDX]}${NC}"
    SPIN_IDX=$(( (SPIN_IDX + 1) % ${#SPINNER[@]} ))
}

# ===========================================================================
# Data Structures
# ===========================================================================
# Lanes
declare -a LANE_ORDER=()
declare -A LANE_DISPLAY=()
declare -A LANE_TASKS=()

# Tasks
declare -a TASK_ORDER=()
declare -A TASK_DISPLAY=()
declare -A TASK_LANE=()
declare -A TASK_STATUS=()     # running | done | failed | killed
declare -A TASK_START=()
declare -A TASK_END=()
declare -A TASK_EXIT=()
declare -A TASK_PID=()        # safe_name -> PID (reverse of PID_TO_TASK)

# PID tracking
declare -A PID_TO_TASK=()
declare -a ACTIVE_PIDS=()

# Counters
TOTAL_COUNT=0
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
KILL_COUNT=0

# Fail-fast flag
FAIL_FAST_TRIGGERED=false

# Render state
RENDER_DRAWN=false
DISPLAY_LINES=0

# E2E test groups (populated by discover_and_classify_tests)
declare -A E2E_GROUPS=()
declare -A E2E_GROUP_COUNTS=()
declare -A GROUP_LABELS=(
    [ssh_socks5]="SSH & SOCKS5"
    [acl_security]="ACL & Security"
    [api_dashboard]="API & Dashboard"
    [integrations]="Integrations"
    [catchall]="Catchall"
)

# Tool availability
ACT_AVAILABLE=false
PODMAN_AVAILABLE=false
DOCKER_AVAILABLE=false
LLVM_COV_AVAILABLE=false
MSRV_AVAILABLE=false
VHS_AVAILABLE=false
VHS_VIA=""
VHS_FONT_OK=false
AUDIT_AVAILABLE=false
DENY_AVAILABLE=false
TRIVY_AVAILABLE=false
TRIVY_VIA=""
GRYPE_AVAILABLE=false
GRYPE_VIA=""

# ===========================================================================
# Cleanup
# ===========================================================================
cleanup() {
    # Kill child processes (cargo, rustc, etc.) before subshell parents
    # to prevent orphaned builds writing to target/
    for pid in "${ACTIVE_PIDS[@]}"; do
        pkill -TERM -P "$pid" 2>/dev/null || true
    done
    for pid in "${ACTIVE_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 0.3
    for pid in "${ACTIVE_PIDS[@]}"; do
        pkill -KILL -P "$pid" 2>/dev/null || true
        kill -KILL "$pid" 2>/dev/null || true
    done
    # Kill stray children (tickers, etc.)
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    ACTIVE_PIDS=()
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ===========================================================================
# Tool Detection
# ===========================================================================
tool_label() {
    if $1; then printf '%b' "${GREEN}ok${NC} $2"; else printf '%b' "${DIM}--${NC} ${DIM}$2${NC}"; fi
}

tool_label_via() {
    local available="$1" name="$2" via="$3"
    if $available; then
        if [[ "$via" == "native" ]]; then
            printf '%b' "${GREEN}ok${NC} $name"
        else
            printf '%b' "${GREEN}ok${NC} $name ${DIM}($via)${NC}"
        fi
    else
        printf '%b' "${DIM}--${NC} ${DIM}$name${NC}"
    fi
}

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

    # trivy: native -> podman -> docker
    if command -v trivy &>/dev/null; then
        local trivy_bin
        trivy_bin=$(command -v trivy)
        if file "$trivy_bin" 2>/dev/null | grep -q 'ELF'; then
            TRIVY_AVAILABLE=true; TRIVY_VIA="native"
        elif grep -q 'podman run' "$trivy_bin" 2>/dev/null; then
            TRIVY_AVAILABLE=true; TRIVY_VIA="podman"
        elif grep -q 'docker run' "$trivy_bin" 2>/dev/null; then
            TRIVY_AVAILABLE=true; TRIVY_VIA="docker"
        else
            TRIVY_AVAILABLE=true; TRIVY_VIA="native"
        fi
    elif $PODMAN_AVAILABLE; then
        TRIVY_AVAILABLE=true; TRIVY_VIA="podman"
    elif $DOCKER_AVAILABLE; then
        TRIVY_AVAILABLE=true; TRIVY_VIA="docker"
    fi

    # grype: native -> podman -> docker
    if command -v grype &>/dev/null; then
        local grype_bin
        grype_bin=$(command -v grype)
        if file "$grype_bin" 2>/dev/null | grep -q 'ELF'; then
            GRYPE_AVAILABLE=true; GRYPE_VIA="native"
        elif grep -q 'podman run' "$grype_bin" 2>/dev/null; then
            GRYPE_AVAILABLE=true; GRYPE_VIA="podman"
        elif grep -q 'docker run' "$grype_bin" 2>/dev/null; then
            GRYPE_AVAILABLE=true; GRYPE_VIA="docker"
        else
            GRYPE_AVAILABLE=true; GRYPE_VIA="native"
        fi
    elif $PODMAN_AVAILABLE; then
        GRYPE_AVAILABLE=true; GRYPE_VIA="podman"
    elif $DOCKER_AVAILABLE; then
        GRYPE_AVAILABLE=true; GRYPE_VIA="docker"
    fi

    # vhs: native -> podman -> docker
    if command -v vhs &>/dev/null; then
        local vhs_bin
        vhs_bin=$(command -v vhs)
        if file "$vhs_bin" 2>/dev/null | grep -q 'ELF'; then
            VHS_AVAILABLE=true; VHS_VIA="native"
        elif grep -q 'podman run' "$vhs_bin" 2>/dev/null; then
            VHS_AVAILABLE=true; VHS_VIA="podman"
        elif grep -q 'docker run' "$vhs_bin" 2>/dev/null; then
            VHS_AVAILABLE=true; VHS_VIA="docker"
        else
            VHS_AVAILABLE=true; VHS_VIA="native"
        fi
    elif $PODMAN_AVAILABLE; then
        VHS_AVAILABLE=true; VHS_VIA="podman"
    elif $DOCKER_AVAILABLE; then
        VHS_AVAILABLE=true; VHS_VIA="docker"
    fi

    # VHS font check: JetBrains Mono required for tape recordings
    if $VHS_AVAILABLE; then
        if fc-list 2>/dev/null | grep -qi "JetBrains Mono"; then
            VHS_FONT_OK=true
        else
            VHS_AVAILABLE=false
            VHS_VIA="no font"
        fi
    fi

    echo -e "${CYAN}[Tools]${NC} " \
        "$(tool_label $ACT_AVAILABLE act) " \
        "$(tool_label $PODMAN_AVAILABLE podman) " \
        "$(tool_label $LLVM_COV_AVAILABLE llvm-cov) " \
        "$(tool_label $MSRV_AVAILABLE 'MSRV 1.88') " \
        "$(tool_label $AUDIT_AVAILABLE audit) " \
        "$(tool_label $DENY_AVAILABLE deny) " \
        "$(tool_label_via $TRIVY_AVAILABLE trivy "$TRIVY_VIA") " \
        "$(tool_label_via $GRYPE_AVAILABLE grype "$GRYPE_VIA") " \
        "$(tool_label_via $VHS_AVAILABLE vhs "$VHS_VIA")"

    local ver branch commit dirty=""
    ver=$(sed -n 's/^version = "\(.*\)"/\1/p' "$PROJECT_ROOT/Cargo.toml" | head -1)
    branch=$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "?")
    commit=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "?")
    git -C "$PROJECT_ROOT" diff --quiet HEAD 2>/dev/null || dirty=" ${YELLOW}(dirty)${NC}"
    echo -e "${CYAN}[Build]${NC}  ${BOLD}${ver}${NC} | ${branch} @ ${commit}${dirty}"
}

# ===========================================================================
# Container Commands (trivy, grype, vhs)
# ===========================================================================
trivy_command() {
    case "$TRIVY_VIA" in
        native) echo "trivy" ;;
        podman) echo "podman run --rm -v ${XDG_RUNTIME_DIR}/podman/podman.sock:/var/run/docker.sock:ro -v ${PROJECT_ROOT}:${PROJECT_ROOT}:ro -w ${PROJECT_ROOT} ghcr.io/aquasecurity/trivy:latest" ;;
        docker) echo "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v ${PROJECT_ROOT}:${PROJECT_ROOT}:ro -w ${PROJECT_ROOT} ghcr.io/aquasecurity/trivy:latest" ;;
    esac
}

trivy_image_src() {
    case "$TRIVY_VIA" in
        native) echo "podman" ;;
        podman|docker) echo "docker" ;;
    esac
}

grype_command() {
    case "$GRYPE_VIA" in
        native) echo "grype" ;;
        podman) echo "podman run --rm -v ${XDG_RUNTIME_DIR}/podman/podman.sock:/var/run/docker.sock:ro -v ${PROJECT_ROOT}:${PROJECT_ROOT}:ro -w ${PROJECT_ROOT} docker.io/anchore/grype:latest" ;;
        docker) echo "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock:ro -v ${PROJECT_ROOT}:${PROJECT_ROOT}:ro -w ${PROJECT_ROOT} docker.io/anchore/grype:latest" ;;
    esac
}

grype_image_prefix() {
    case "$GRYPE_VIA" in
        native) echo "podman:" ;;
        podman|docker) echo "docker:" ;;
    esac
}

vhs_command() {
    case "$VHS_VIA" in
        native) echo "vhs" ;;
        podman) echo "podman run --rm -v ${PWD}:/vhs ghcr.io/charmbracelet/vhs" ;;
        docker) echo "docker run --rm -v ${PWD}:/vhs ghcr.io/charmbracelet/vhs" ;;
    esac
}

# ===========================================================================
# CVE Ignore Expiry Check
# ===========================================================================
check_ignore_expiry() {
    local today has_expired=false
    today=$(date +%Y-%m-%d)

    if [[ -f "$PROJECT_ROOT/.grype.yaml" ]]; then
        while IFS= read -r line; do
            local exp_date
            exp_date=$(echo "$line" | sed -n 's/.*#[[:space:]]*expires:[[:space:]]*\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\).*/\1/p')
            if [[ -n "$exp_date" ]] && [[ "$today" > "$exp_date" || "$today" == "$exp_date" ]]; then
                local cve=""
                cve=$(grep -B5 "$exp_date" "$PROJECT_ROOT/.grype.yaml" | sed -n 's/.*vulnerability:[[:space:]]*\(CVE-[^ ]*\).*/\1/p' | tail -1)
                echo -e "  ${RED}!!${NC} Expired CVE ignore: ${cve:-unknown} (expired $exp_date)"
                has_expired=true
            fi
        done < "$PROJECT_ROOT/.grype.yaml"
    fi

    if [[ -f "$PROJECT_ROOT/.trivyignore" ]]; then
        while IFS= read -r line; do
            local exp_date
            exp_date=$(echo "$line" | sed -n 's/.*expires:[[:space:]]*\([0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\}\).*/\1/p')
            if [[ -n "$exp_date" ]] && [[ "$today" > "$exp_date" || "$today" == "$exp_date" ]]; then
                local cve
                cve=$(echo "$line" | sed -n 's/^\(CVE-[^ ]*\).*/\1/p')
                if [[ -z "$cve" ]]; then
                    cve=$(sed -n "/$exp_date/{x;p;d;}; x" "$PROJECT_ROOT/.trivyignore" | sed -n 's/^\(CVE-[^ ]*\).*/\1/p')
                fi
                echo -e "  ${RED}!!${NC} Expired CVE ignore: ${cve:-unknown} (expired $exp_date)"
                has_expired=true
            fi
        done < "$PROJECT_ROOT/.trivyignore"
    fi

    if $has_expired; then
        echo -e "  ${YELLOW}!!${NC} Remove expired entries or update the expiry date"
        return 1
    fi
    return 0
}

# ===========================================================================
# Test Discovery & Classification
# ===========================================================================
discover_e2e_tests() {
    sed -n '/^\[\[test\]\]/,/^$/p' "$PROJECT_ROOT/Cargo.toml" | \
        grep '^name' | sed 's/.*"\(.*\)"/\1/' | \
        grep '^e2e_' | grep -v '^e2e_browser'
}

classify_test() {
    local test="$1"
    case "$test" in
        e2e_auth|e2e_ssh*|e2e_socks5*|e2e_forwarding|e2e_rejection)
            echo "ssh_socks5" ;;
        e2e_acl*|e2e_autoban|e2e_shell*|e2e_upstream*)
            echo "acl_security" ;;
        e2e_api*|e2e_quota*|e2e_status|e2e_cli)
            echo "api_dashboard" ;;
        e2e_audit*|e2e_webhook*|e2e_sse*|e2e_ws|e2e_metrics*|e2e_backup*|e2e_persistence|e2e_reload|e2e_performance)
            echo "integrations" ;;
        *)
            echo "catchall" ;;
    esac
}

discover_and_classify_tests() {
    while IFS= read -r test; do
        local group
        group=$(classify_test "$test")
        E2E_GROUPS[$group]+=" --test $test"
        E2E_GROUP_COUNTS[$group]=$(( ${E2E_GROUP_COUNTS[$group]:-0} + 1 ))
    done < <(discover_e2e_tests)
}

# ===========================================================================
# Lane & Task Registration
# ===========================================================================
register_lane() {
    local id="$1" display="$2"
    LANE_ORDER+=("$id")
    LANE_DISPLAY["$id"]="$display"
    LANE_TASKS["$id"]=""
}

# ===========================================================================
# Core Engine: run_task
# ===========================================================================
run_task() {
    local name="$1" lane="$2"
    shift 2
    local safe_name
    safe_name=$(echo "$name" | tr -cs 'a-zA-Z0-9._-' '_')

    # Deduplicate safe_name (append counter if collision)
    if [[ -n "${TASK_STATUS[$safe_name]:-}" ]]; then
        local suffix=2
        while [[ -n "${TASK_STATUS[${safe_name}_${suffix}]:-}" ]]; do
            suffix=$(( suffix + 1 ))
        done
        safe_name="${safe_name}_${suffix}"
    fi

    # Register task
    TASK_ORDER+=("$safe_name")
    TASK_DISPLAY["$safe_name"]="$name"
    TASK_LANE["$safe_name"]="$lane"
    TASK_STATUS["$safe_name"]="running"
    TASK_START["$safe_name"]=$SECONDS
    TOTAL_COUNT=$(( TOTAL_COUNT + 1 ))

    # Add to lane
    if [[ -z "${LANE_TASKS[$lane]:-}" ]]; then
        LANE_TASKS[$lane]="$safe_name"
    else
        LANE_TASKS[$lane]+=" $safe_name"
    fi

    # Plain mode: log start
    if ! $PRETTY_MODE; then
        echo -e "  ${DIM}>>${NC} $name ${DIM}[$lane]${NC}"
    fi

    # Launch in subshell: run command, then write exit code to sentinel file
    ( "$@" > "$TMP_DIR/log.$safe_name" 2>&1; echo "$?" > "$TMP_DIR/exit.$safe_name" ) &
    local pid=$!

    PID_TO_TASK[$pid]="$safe_name"
    TASK_PID["$safe_name"]=$pid
    ACTIVE_PIDS+=("$pid")
}

skip_task() {
    local name="$1"
    SKIP_COUNT=$(( SKIP_COUNT + 1 ))
    if ! $PRETTY_MODE; then
        echo -e "  ${YELLOW}--${NC} $name ${DIM}(skipped)${NC}"
    fi
}

# ===========================================================================
# Core Engine: PID management
# ===========================================================================
remove_pid() {
    local target="$1"
    local -a new=()
    for pid in "${ACTIVE_PIDS[@]}"; do
        [[ "$pid" != "$target" ]] && new+=("$pid")
    done
    ACTIVE_PIDS=("${new[@]+"${new[@]}"}")
}

# ===========================================================================
# Core Engine: handle task completion (by safe_name, not PID)
# ===========================================================================
complete_task() {
    local safe_name="$1" rc="$2"

    # Reap zombie and clean up PID tracking
    local pid="${TASK_PID[$safe_name]:-}"
    if [[ -n "$pid" ]]; then
        remove_pid "$pid"
        unset "PID_TO_TASK[$pid]"
        wait "$pid" 2>/dev/null || true
    fi

    TASK_END["$safe_name"]=$SECONDS
    TASK_EXIT["$safe_name"]="$rc"
    local duration=$(( TASK_END["$safe_name"] - TASK_START["$safe_name"] ))
    local name="${TASK_DISPLAY[$safe_name]}"

    if (( rc == 0 )); then
        TASK_STATUS["$safe_name"]="done"
        PASS_COUNT=$(( PASS_COUNT + 1 ))
        if ! $PRETTY_MODE; then
            printf "  ${GREEN}%-2s${NC} %-38s ${DIM}%s${NC}\n" "ok" "$name" "${duration}s"
        fi
        # Launch dependent tasks
        maybe_launch_dependents "$safe_name"
    else
        TASK_STATUS["$safe_name"]="failed"
        FAIL_COUNT=$(( FAIL_COUNT + 1 ))
        if ! $PRETTY_MODE; then
            printf "  ${RED}%-2s${NC} %-38s ${DIM}%s${NC}\n" "!!" "$name" "${duration}s"
        fi
        FAIL_FAST_TRIGGERED=true
    fi
}

# ===========================================================================
# Core Engine: dependency chaining
# ===========================================================================
maybe_launch_dependents() {
    local safe_name="$1"
    local task_name="${TASK_DISPLAY[$safe_name]}"

    case "$task_name" in
        "Clippy")
            run_task "Compile tests" "Cargo" cargo test --all-targets --no-run
            ;;
        "Compile tests")
            # Launch test execution tasks (binaries are ready)
            run_task "Unit tests" "Cargo" cargo test --lib --test unit
            for group in ssh_socks5 acl_security api_dashboard integrations catchall; do
                if [[ -n "${E2E_GROUPS[$group]:-}" ]]; then
                    # shellcheck disable=SC2086
                    run_task "E2E: ${GROUP_LABELS[$group]}" "Cargo" cargo test ${E2E_GROUPS[$group]}
                fi
            done
            # Browser E2E (needs compiled binaries + Podman)
            if ! $SKIP_BROWSER && $PODMAN_AVAILABLE; then
                run_task "Browser E2E" "Browser" bash -c 'make test-e2e-browser && make test-screenshots'
            fi
            ;;
        "Docker Build")
            # Launch scan tasks (images are ready)
            if $TRIVY_AVAILABLE; then
                local trivy_cmd trivy_src
                trivy_cmd=$(trivy_command)
                trivy_src=$(trivy_image_src)
                run_task "Trivy scan" "Docker" bash -c \
                    "$trivy_cmd image --image-src $trivy_src --exit-code 1 --severity CRITICAL,HIGH,MEDIUM --ignorefile .trivyignore sks5:latest && $trivy_cmd image --image-src $trivy_src --exit-code 1 --severity CRITICAL,HIGH,MEDIUM --ignorefile .trivyignore sks5:scratch"
            fi
            if $GRYPE_AVAILABLE; then
                local grype_cmd grype_prefix
                grype_cmd=$(grype_command)
                grype_prefix=$(grype_image_prefix)
                run_task "Grype scan" "Docker" bash -c \
                    "$grype_cmd ${grype_prefix}sks5:latest --fail-on medium -c .grype.yaml && $grype_cmd ${grype_prefix}sks5:scratch --fail-on medium -c .grype.yaml"
            fi
            ;;
    esac
}

# ===========================================================================
# Core Engine: fail-fast kill
# ===========================================================================
kill_all_active() {
    # Mark remaining running tasks as killed
    for pid in "${ACTIVE_PIDS[@]}"; do
        local sn="${PID_TO_TASK[$pid]:-}"
        if [[ -n "$sn" ]]; then
            TASK_STATUS["$sn"]="killed"
            TASK_END["$sn"]=$SECONDS
            TASK_EXIT["$sn"]="killed"
            KILL_COUNT=$(( KILL_COUNT + 1 ))
        fi
    done

    # SIGTERM children first (cargo, rustc, etc.), then subshell parents.
    # Bash subshells queue SIGTERM while a foreground command runs — the
    # child process never receives it, becomes orphaned (reparented to
    # PID 1), and keeps writing to target/.  Sending SIGTERM to children
    # explicitly via pkill -P avoids this.
    for pid in "${ACTIVE_PIDS[@]}"; do
        pkill -TERM -P "$pid" 2>/dev/null || true
    done
    for pid in "${ACTIVE_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done

    # Grace period (up to 5s — cargo may need time to finish a link step)
    local attempts=0
    while (( attempts < 25 )); do
        local alive=false
        for pid in "${ACTIVE_PIDS[@]}"; do
            kill -0 "$pid" 2>/dev/null && alive=true && break
        done
        $alive || break
        sleep 0.2
        attempts=$(( attempts + 1 ))
    done

    # SIGKILL remaining process trees
    for pid in "${ACTIVE_PIDS[@]}"; do
        pkill -KILL -P "$pid" 2>/dev/null || true
        kill -KILL "$pid" 2>/dev/null || true
    done

    wait 2>/dev/null || true
    ACTIVE_PIDS=()
}

# ===========================================================================
# Display: Pretty Mode Renderer
# ===========================================================================
compute_lane_line() {
    local lane="$1"
    local tasks_str="${LANE_TASKS[$lane]:-}"
    local display="${LANE_DISPLAY[$lane]}"

    # Empty lane (registered but no tasks yet)
    if [[ -z "$tasks_str" ]]; then
        printf "  ${DIM}[%-8s]${NC}  %b %-30s %4s" "$display" "$SYM_WAIT" "waiting" "-"
        return
    fi

    local -a tasks=($tasks_str)
    local running=0 done_count=0 failed=0 killed=0 total=${#tasks[@]}
    local current_task="" lane_start="" lane_end=""
    local has_failed_name=""

    for t in "${tasks[@]}"; do
        local st="${TASK_STATUS[$t]:-pending}"
        local ts="${TASK_START[$t]:-}"
        local te="${TASK_END[$t]:-}"
        case "$st" in
            running)
                running=$((running + 1))
                current_task="${TASK_DISPLAY[$t]}"
                if [[ -z "$lane_start" ]] || (( ts < lane_start )); then
                    lane_start="$ts"
                fi
                ;;
            done)
                done_count=$((done_count + 1))
                if [[ -z "$lane_start" ]] || (( ts < lane_start )); then
                    lane_start="$ts"
                fi
                if [[ -z "$lane_end" ]] || (( te > lane_end )); then
                    lane_end="$te"
                fi
                ;;
            failed)
                failed=$((failed + 1))
                has_failed_name="${TASK_DISPLAY[$t]}"
                if [[ -z "$lane_start" ]] || (( ts < lane_start )); then
                    lane_start="$ts"
                fi
                if [[ -n "$te" ]]; then
                    if [[ -z "$lane_end" ]] || (( te > lane_end )); then
                        lane_end="$te"
                    fi
                fi
                ;;
            killed)
                killed=$((killed + 1))
                ;;
        esac
    done

    # Compute duration display
    local dur_str="-"
    if [[ -n "$lane_start" ]]; then
        if (( running > 0 )); then
            dur_str="$(( SECONDS - lane_start ))s"
        elif [[ -n "$lane_end" ]]; then
            dur_str="$(( lane_end - lane_start ))s"
        fi
    fi

    # Determine symbol and text
    local symbol text
    if (( failed > 0 )); then
        symbol="$SYM_FAIL"
        text="FAILED: $has_failed_name"
    elif (( killed > 0 && running == 0 && done_count + killed == total )); then
        symbol="$SYM_KILL"
        text="killed"
    elif (( running > 0 )); then
        symbol="$(get_spinner)"
        if (( running > 1 )); then
            text="${done_count}/${total} done, ${running} running"
        else
            text="$current_task"
        fi
    elif (( done_count == total )); then
        symbol="$SYM_OK"
        if (( total == 1 )); then
            text="${TASK_DISPLAY[${tasks[0]}]}"
        else
            text="${done_count}/${total} tasks"
        fi
    else
        symbol="$SYM_WAIT"
        text="waiting"
    fi

    printf "  [%-8s]  %b %-30s %4s" "$display" "$symbol" "$text" "$dur_str"
}

render() {
    if ! $PRETTY_MODE; then return; fi

    local elapsed=$(( SECONDS - TOTAL_START ))
    local active_lanes=0 done_lanes=0

    # Count active lanes
    for lane in "${LANE_ORDER[@]}"; do
        local tasks_str="${LANE_TASKS[$lane]:-}"
        if [[ -z "$tasks_str" ]]; then continue; fi
        local has_running=false all_done=true
        for t in $tasks_str; do
            case "${TASK_STATUS[$t]:-pending}" in
                running) has_running=true; all_done=false ;;
                done) ;;
                *) all_done=false ;;
            esac
        done
        if $has_running; then active_lanes=$((active_lanes + 1)); fi
        if $all_done && [[ -n "$tasks_str" ]]; then done_lanes=$((done_lanes + 1)); fi
    done

    # Build output
    local lines=()
    lines+=("$(printf "  ${BOLD}sks5 Validation${NC} ─ %d lanes, %d tasks" "${#LANE_ORDER[@]}" "$TOTAL_COUNT")")
    lines+=("  $(printf '%0.s─' {1..48})")

    for lane in "${LANE_ORDER[@]}"; do
        lines+=("$(compute_lane_line "$lane")")
    done

    lines+=("  $(printf '%0.s─' {1..48})")
    lines+=("$(printf "  Progress: %d/%d done │ %d active │ %ds" "$PASS_COUNT" "$TOTAL_COUNT" "$active_lanes" "$elapsed")")

    local total_lines=${#lines[@]}

    # Move cursor up to overwrite previous render
    if $RENDER_DRAWN; then
        printf '\033[%dA' "$DISPLAY_LINES"
    fi
    RENDER_DRAWN=true
    DISPLAY_LINES=$total_lines

    # Print lines (clear each line first)
    for line in "${lines[@]}"; do
        printf '\033[2K%b\n' "$line"
    done
}

# ===========================================================================
# Display: Show Plan (pre-execution summary)
# ===========================================================================
show_plan() {
    local run_count=0
    local -a not_covered=()

    echo ""
    echo -e "${BOLD}  Will run${NC}"
    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"

    plan_run() { printf "  ${GREEN}%-3s${NC} %-40s %s\n" "RUN" "$1" "${2:-}"; run_count=$((run_count + 1)); }
    plan_not() { not_covered+=("$1"); }

    # Cargo Pipeline
    echo -e "  ${BLUE}${BOLD}Cargo Pipeline${NC}"
    if ! $ACT_AVAILABLE; then
        plan_run "Clippy"
    fi
    plan_run "Compile tests"
    plan_run "Unit tests"
    for group in ssh_socks5 acl_security api_dashboard integrations catchall; do
        local count="${E2E_GROUP_COUNTS[$group]:-0}"
        if (( count > 0 )); then
            plan_run "E2E: ${GROUP_LABELS[$group]}" "${count} tests"
        fi
    done

    # Security
    echo -e "  ${BLUE}${BOLD}Security${NC}"
    if $AUDIT_AVAILABLE; then plan_run "cargo audit"; else plan_not "cargo audit"; fi
    if $DENY_AVAILABLE; then plan_run "cargo deny"; else plan_not "cargo deny"; fi

    # MSRV
    if $MSRV_AVAILABLE; then
        echo -e "  ${BLUE}${BOLD}MSRV${NC}"
        plan_run "MSRV (1.88)" "CARGO_TARGET_DIR=target-msrv"
    else
        plan_not "MSRV (1.88)"
    fi

    # Coverage
    if ! $SKIP_COVERAGE && $LLVM_COV_AVAILABLE; then
        echo -e "  ${BLUE}${BOLD}Coverage${NC}"
        plan_run "llvm-cov" "CARGO_TARGET_DIR=target-cov"
    else
        plan_not "Coverage"
    fi

    # Docker
    if $WITH_DOCKER && $PODMAN_AVAILABLE; then
        echo -e "  ${BLUE}${BOLD}Docker${NC}"
        plan_run "Docker Build"
        if $TRIVY_AVAILABLE; then plan_run "Trivy scan ($TRIVY_VIA)"; else plan_not "Trivy scan"; fi
        if $GRYPE_AVAILABLE; then plan_run "Grype scan ($GRYPE_VIA)"; else plan_not "Grype scan"; fi
    elif ! $WITH_DOCKER; then
        not_covered+=("Docker Build + Scan      -> use: make validate-docker")
    fi

    # Browser
    if ! $SKIP_BROWSER && $PODMAN_AVAILABLE; then
        echo -e "  ${BLUE}${BOLD}Browser${NC}"
        plan_run "Browser E2E + Screenshots"
    else
        plan_not "Browser E2E + Screenshots"
    fi

    # CI / Act
    if $ACT_AVAILABLE; then
        echo -e "  ${BLUE}${BOLD}CI (act)${NC}"
        plan_run "CI Lint + Docker Lint"
    fi

    # VHS
    if $VHS_AVAILABLE; then
        local tape_count=0
        for tape in "$PROJECT_ROOT"/contrib/*.tape; do [[ -f "$tape" ]] && tape_count=$((tape_count + 1)); done
        if (( tape_count > 0 )); then
            echo -e "  ${BLUE}${BOLD}VHS${NC}"
            plan_run "VHS tapes ($VHS_VIA)" "${tape_count} tapes"
        fi
    elif [[ "$VHS_VIA" == "no font" ]]; then
        plan_not "VHS recordings     -> missing JetBrains Mono font (make setup)"
    else
        plan_not "VHS recordings"
    fi

    echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"

    # Not covered
    if (( ${#not_covered[@]} > 0 )); then
        echo ""
        echo -e "${BOLD}  Not covered${NC}"
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
        for entry in "${not_covered[@]}"; do
            echo -e "  ${YELLOW}---${NC} ${entry}"
        done
        echo -e "  ${DIM}──────────────────────────────────────────────────${NC}"
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

# ===========================================================================
# Stale Container Cleanup
# ===========================================================================
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

# ===========================================================================
# Auto-install missing tools
# ===========================================================================
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

# ===========================================================================
# Register all lanes based on detected tools
# ===========================================================================
register_lanes() {
    # Cargo lane always exists
    register_lane "Cargo" "Cargo"

    if $AUDIT_AVAILABLE || $DENY_AVAILABLE; then
        register_lane "Security" "Security"
    fi

    if $MSRV_AVAILABLE; then
        register_lane "MSRV" "MSRV"
    fi

    if ! $SKIP_COVERAGE && $LLVM_COV_AVAILABLE; then
        register_lane "Coverage" "Coverage"
    fi

    if $WITH_DOCKER && $PODMAN_AVAILABLE; then
        register_lane "Docker" "Docker"
    fi

    if ! $SKIP_BROWSER && $PODMAN_AVAILABLE; then
        register_lane "Browser" "Browser"
    fi

    if $ACT_AVAILABLE; then
        register_lane "CI" "CI"
    fi

    if $VHS_AVAILABLE; then
        local tape_count=0
        for tape in "$PROJECT_ROOT"/contrib/*.tape; do [[ -f "$tape" ]] && tape_count=$((tape_count + 1)); done
        if (( tape_count > 0 )); then
            register_lane "VHS" "VHS"
        fi
    fi
}

# ===========================================================================
# Gate: synchronous fast checks (abort immediately on failure)
# ===========================================================================
run_gate() {
    echo -e "${BLUE}${BOLD}[Gate]${NC} ${BOLD}Fast checks${NC}"

    local gate_start=$SECONDS
    if ! cargo fmt --all -- --check > "$TMP_DIR/log.fmt_check" 2>&1; then
        local dur=$(( SECONDS - gate_start ))
        printf "  ${RED}%-2s${NC} %-38s ${DIM}%s${NC}\n" "!!" "fmt --check" "${dur}s"
        echo ""
        echo -e "${RED}Code is not formatted. Run: ${BOLD}cargo fmt${NC}"
        echo -e "${DIM}--- Output ---${NC}"
        tail -20 "$TMP_DIR/log.fmt_check"
        echo -e "${DIM}--- End ---${NC}"
        return 1
    fi
    local dur=$(( SECONDS - gate_start ))
    printf "  ${GREEN}%-2s${NC} %-38s ${DIM}%s${NC}\n" "ok" "fmt --check" "${dur}s"

    local sync_start=$SECONDS
    if ! "$SCRIPT_DIR/check-ci-test-sync.sh" > "$TMP_DIR/log.ci_test_sync" 2>&1; then
        local sdur=$(( SECONDS - sync_start ))
        printf "  ${RED}%-2s${NC} %-38s ${DIM}%s${NC}\n" "!!" "CI test sync" "${sdur}s"
        echo ""
        echo -e "${RED}E2E tests out of sync between Cargo.toml and ci.yml${NC}"
        echo -e "${DIM}--- Output ---${NC}"
        cat "$TMP_DIR/log.ci_test_sync"
        echo -e "${DIM}--- End ---${NC}"
        return 1
    fi
    local sdur=$(( SECONDS - sync_start ))
    printf "  ${GREEN}%-2s${NC} %-38s ${DIM}%s${NC}\n" "ok" "CI test sync" "${sdur}s"

    # Build cache health check: detect corruption left by a previous
    # interrupted run (orphaned cargo processes, killed mid-write, etc.)
    # and auto-recover by cleaning target/.
    if [[ -d target/debug/.fingerprint ]]; then
        local cache_start=$SECONDS
        if ! cargo check > "$TMP_DIR/log.cache_check" 2>&1; then
            if grep -qEi 'possibly newer version|required to be available in .* format|can.t find crate for|inconsistent metadata|compiled by an incompatible version' \
                    "$TMP_DIR/log.cache_check" 2>/dev/null; then
                cargo clean 2>/dev/null
                local cdur=$(( SECONDS - cache_start ))
                printf "  ${YELLOW}%-2s${NC} %-38s ${DIM}%s${NC}\n" "!!" "cache corrupted — auto-cleaned" "${cdur}s"
            fi
            # If it's a real code error, let the main compilation report it.
        else
            local cdur=$(( SECONDS - cache_start ))
            printf "  ${GREEN}%-2s${NC} %-38s ${DIM}%s${NC}\n" "ok" "cache check" "${cdur}s"
        fi
    fi

    # CVE expiry check (only with --with-docker)
    if $WITH_DOCKER; then
        if ! check_ignore_expiry; then
            return 1
        fi
    fi

    echo ""
    return 0
}

# ===========================================================================
# Launch initial tasks (no dependencies)
# ===========================================================================
launch_initial_tasks() {
    # --- Cargo Pipeline ---
    if $ACT_AVAILABLE; then
        # Act handles linting; start compilation directly
        run_task "Compile tests" "Cargo" cargo test --all-targets --no-run
    else
        # Local lint first, then compile (chained via maybe_launch_dependents)
        run_task "Clippy" "Cargo" cargo clippy --all-targets -- -D warnings
    fi

    # --- Security ---
    if $AUDIT_AVAILABLE; then
        run_task "cargo audit" "Security" cargo audit
    else
        skip_task "cargo audit (not installed)"
    fi
    if $DENY_AVAILABLE; then
        run_task "cargo deny" "Security" cargo deny check
    else
        skip_task "cargo deny (not installed)"
    fi

    # --- MSRV (own target dir for true parallelism) ---
    if $MSRV_AVAILABLE; then
        run_task "MSRV (1.88)" "MSRV" env CARGO_TARGET_DIR=target-msrv cargo +1.88 check
    else
        skip_task "MSRV (toolchain 1.88 not installed)"
    fi

    # --- Coverage (own target dir for true parallelism) ---
    if ! $SKIP_COVERAGE && $LLVM_COV_AVAILABLE; then
        run_task "Coverage" "Coverage" env CARGO_TARGET_DIR=target-cov cargo llvm-cov --lcov --output-path lcov.info --lib --test unit
    else
        if $SKIP_COVERAGE; then
            skip_task "Coverage (--skip-coverage)"
        elif ! $LLVM_COV_AVAILABLE; then
            skip_task "Coverage (cargo-llvm-cov not available)"
        fi
    fi

    # --- Docker Pipeline ---
    if $WITH_DOCKER && $PODMAN_AVAILABLE; then
        run_task "Docker Build" "Docker" make docker-build-all
    elif $WITH_DOCKER; then
        skip_task "Docker Build (podman not available)"
    fi

    # --- CI / Act ---
    if $ACT_AVAILABLE; then
        cleanup_act_containers
        run_task "CI Lint (act)" "CI" bash -c 'make ci-lint && make ci-docker-lint'
    fi

    # --- VHS ---
    if $VHS_AVAILABLE; then
        local vhs_cmd
        vhs_cmd=$(vhs_command)
        for tape in "$PROJECT_ROOT"/contrib/*.tape; do
            if [[ -f "$tape" ]]; then
                local tape_name tape_path
                tape_name=$(basename "$tape" .tape)
                if [[ "$VHS_VIA" == "native" ]]; then
                    tape_path="$tape"
                else
                    tape_path="${tape#"$PROJECT_ROOT"/}"
                fi
                # shellcheck disable=SC2086
                run_task "VHS: $tape_name" "VHS" $vhs_cmd "$tape_path"
            fi
        done
    fi

    # --- Browser E2E: launched later via maybe_launch_dependents("Compile tests") ---
    if $SKIP_BROWSER; then
        skip_task "Browser E2E (--skip-browser)"
    elif ! $PODMAN_AVAILABLE; then
        skip_task "Browser E2E (podman not available)"
    fi
}

# ===========================================================================
# Reaper Loop: poll sentinel exit files for task completions
# ===========================================================================
reap_loop() {
    $PRETTY_MODE && render

    while (( ${#ACTIVE_PIDS[@]} > 0 )); do
        local found_completion=false

        # Scan all running tasks for sentinel exit files
        # Note: TASK_ORDER may grow during this loop (via maybe_launch_dependents),
        # but for-in expands the array at loop start, so new tasks are picked up
        # on the next iteration of the outer while loop.
        for t in "${TASK_ORDER[@]}"; do
            [[ "${TASK_STATUS[$t]}" != "running" ]] && continue

            local exit_file="$TMP_DIR/exit.$t"
            if [[ -f "$exit_file" ]]; then
                local rc
                rc=$(<"$exit_file")

                complete_task "$t" "$rc"
                found_completion=true

                $PRETTY_MODE && render

                if $FAIL_FAST_TRIGGERED; then
                    kill_all_active
                    $PRETTY_MODE && render
                    return
                fi
            fi
        done

        # Refresh display / wait for next poll cycle
        $PRETTY_MODE && render

        if ! $found_completion; then
            sleep 0.3
        fi
    done
}

# ===========================================================================
# Show Task Log (for failed tasks)
# ===========================================================================
show_task_log() {
    local safe_name="$1"
    local name="${TASK_DISPLAY[$safe_name]}"
    local log_file="$TMP_DIR/log.$safe_name"
    if [[ -f "$log_file" ]] && [[ -s "$log_file" ]]; then
        echo ""
        echo -e "${DIM}--- Output: $name ---${NC}"
        tail -50 "$log_file"
        echo -e "${DIM}--- End ---${NC}"
    fi
}

# ===========================================================================
# Summary: Gantt Chart
# ===========================================================================
print_gantt() {
    local total_time=$(( SECONDS - TOTAL_START ))
    (( total_time < 1 )) && total_time=1
    local bar_width=35

    echo -e "  ${BOLD}Timeline${NC} ${DIM}(1 char ≈ $(( (total_time + bar_width - 1) / bar_width ))s)${NC}"
    echo ""

    for lane in "${LANE_ORDER[@]}"; do
        local tasks_str="${LANE_TASKS[$lane]:-}"
        [[ -z "$tasks_str" ]] && continue

        local -a tasks=($tasks_str)
        local lane_min=$total_time lane_max=0

        # Compute lane time span
        for t in "${tasks[@]}"; do
            local ts=$(( ${TASK_START[$t]:-$SECONDS} - TOTAL_START ))
            local te=$(( ${TASK_END[$t]:-$SECONDS} - TOTAL_START ))
            (( ts < lane_min )) && lane_min=$ts
            (( te > lane_max )) && lane_max=$te
        done
        local lane_dur=$(( lane_max - lane_min ))

        # Lane header bar
        local bar="" lane_color="$GREEN"
        for t in "${tasks[@]}"; do
            [[ "${TASK_STATUS[$t]}" == "failed" ]] && lane_color="$RED" && break
        done
        local ls=$(( lane_min * bar_width / total_time ))
        local le=$(( lane_max * bar_width / total_time ))
        (( le <= ls )) && le=$(( ls + 1 ))
        (( le > bar_width )) && le=$bar_width
        for (( i = 0; i < bar_width; i++ )); do
            if (( i >= ls && i < le )); then
                bar+="${lane_color}█${NC}"
            else
                bar+="░"
            fi
        done
        printf "  ${BOLD}%-22s${NC} %b %3ds\n" "${LANE_DISPLAY[$lane]}" "$bar" "$lane_dur"

        # Individual tasks (indented)
        for t in "${tasks[@]}"; do
            local name="${TASK_DISPLAY[$t]}"
            local ts=$(( ${TASK_START[$t]:-$SECONDS} - TOTAL_START ))
            local te=$(( ${TASK_END[$t]:-$SECONDS} - TOTAL_START ))
            local d=$(( te - ts ))

            local tbar="" tcolor="$GREEN" tfill="█"
            case "${TASK_STATUS[$t]}" in
                failed) tcolor="$RED" ;;
                killed) tcolor="$DIM" ;;
            esac

            local tls=$(( ts * bar_width / total_time ))
            local tle=$(( te * bar_width / total_time ))
            (( tle <= tls )) && tle=$(( tls + 1 ))
            (( tle > bar_width )) && tle=$bar_width
            for (( i = 0; i < bar_width; i++ )); do
                if (( i >= tls && i < tle )); then
                    tbar+="${tcolor}${tfill}${NC}"
                else
                    tbar+="░"
                fi
            done
            printf "    %-20s %b %3ds\n" "$name" "$tbar" "$d"
        done
    done
}

# ===========================================================================
# Summary
# ===========================================================================
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

    # Compute CPU time (sum of all task durations)
    local cpu_time=0
    for t in "${TASK_ORDER[@]}"; do
        if [[ "${TASK_STATUS[$t]}" == "done" ]] || [[ "${TASK_STATUS[$t]}" == "failed" ]]; then
            local d=$(( ${TASK_END[$t]} - ${TASK_START[$t]} ))
            cpu_time=$(( cpu_time + d ))
        fi
    done
    local speedup="1.0"
    if (( total_time > 0 && cpu_time > 0 )); then
        speedup=$(awk "BEGIN { printf \"%.1f\", $cpu_time / $total_time }")
    fi

    echo ""
    echo -e "${BOLD}=========================================${NC}"

    if [[ $FAIL_COUNT -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}  ✓ All ${PASS_COUNT} checks passed (${time_str})${NC}"
        if (( SKIP_COUNT > 0 )); then
            echo -e "${DIM}  (${SKIP_COUNT} skipped)${NC}"
        fi
    else
        echo -e "${RED}${BOLD}  ✗ ${FAIL_COUNT}/${TOTAL_COUNT} checks failed (${time_str})${NC}"
        if (( SKIP_COUNT > 0 )); then
            echo -e "${DIM}  (${SKIP_COUNT} skipped, ${KILL_COUNT} killed)${NC}"
        fi
    fi

    echo -e "${DIM}  Wall: ${time_str} │ CPU: ${cpu_time}s │ Speedup: ${speedup}x${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""

    # Gantt chart
    if (( ${#TASK_ORDER[@]} > 0 )); then
        print_gantt
    fi

    echo ""
    echo -e "${BOLD}=========================================${NC}"

    # Show failure details
    if (( FAIL_COUNT > 0 )); then
        echo ""
        echo -e "${RED}  Failures:${NC}"
        for t in "${TASK_ORDER[@]}"; do
            if [[ "${TASK_STATUS[$t]}" == "failed" ]]; then
                local name="${TASK_DISPLAY[$t]}"
                local lane="${TASK_LANE[$t]}"
                echo -e "  ${RED}✗${NC} ${lane} > ${name}"
            fi
        done

        # Show logs for failed tasks
        for t in "${TASK_ORDER[@]}"; do
            if [[ "${TASK_STATUS[$t]}" == "failed" ]]; then
                show_task_log "$t"
            fi
        done

        echo ""
        echo -e "${BOLD}=========================================${NC}"
        echo ""
    fi

    if (( FAIL_COUNT > 0 )); then
        return 1
    fi
    return 0
}

# ===========================================================================
# Main
# ===========================================================================
main() {
    echo ""
    echo -e "${BOLD}=========================================${NC}"
    echo -e "${BOLD}  sks5 Comprehensive Validation${NC}"
    echo -e "${BOLD}=========================================${NC}"
    echo ""

    if $DRY_RUN; then
        echo -e "${YELLOW}[DRY RUN] Showing planned execution without running commands${NC}"
        echo ""
    fi

    detect_tools
    discover_and_classify_tests
    show_plan

    if $DRY_RUN; then
        exit 0
    fi

    auto_install

    # Gate: fast synchronous checks
    if ! run_gate; then
        exit 1
    fi

    # Register lanes and launch parallel work
    register_lanes

    # Pretty mode: print header for dashboard
    if $PRETTY_MODE; then
        echo -e "${BLUE}${BOLD}[Running]${NC} ${BOLD}All lanes in parallel${NC}"
        echo ""
    else
        echo -e "${BLUE}${BOLD}[Running]${NC} ${BOLD}All lanes in parallel${NC}"
        echo ""
    fi

    launch_initial_tasks
    reap_loop
    summary
}

main "$@"
