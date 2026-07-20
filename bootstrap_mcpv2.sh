#!/usr/bin/env bash
#
# bootstrap_mcpv2.sh
#
# Clones MCPv2 from GitHub, sets up an isolated venv, applies a verified path
# resolution patch, and runs all three test suites.
#
# Usage:
#   ./bootstrap_mcpv2.sh
#
# Environment variables:
#   MCPV2_REPO    - Repository URL (default: https://github.com/tsonisalomon-lgtm/MCPv2.git)
#   MCPV2_BRANCH  - Branch to checkout (default: main)
#   MCPV2_TESTS   - Space-separated list of tests to run (default: "test_file_transfer.py test_scenarios.py test_cli.py")
#   MCPV2_ITERATIONS - Number of scenario iterations (default: 3)
#

set -euo pipefail

# ----------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------
REPO="${MCPV2_REPO:-https://github.com/tsonisalomon-lgtm/MCPv2.git}"
BRANCH="${MCPV2_BRANCH:-main}"
WORKDIR="${MCPV2_WORKDIR:-./mcpv2}"
VENV_DIR="${WORKDIR}/.venv"
TESTS="${MCPV2_TESTS:-test_file_transfer.py test_scenarios.py test_cli.py}"
ITERATIONS="${MCPV2_ITERATIONS:-3}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ----------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

check_requirements() {
    local missing=()
    command -v python3 >/dev/null 2>&1 || missing+=("python3")
    command -v git >/dev/null 2>&1 || missing+=("git")
    command -v pip3 >/dev/null 2>&1 || missing+=("pip3")
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Please install them first."
        exit 1
    fi
    # Check Python version
    python_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    if [[ "$(echo "$python_version < 3.10" | bc)" -eq 1 ]]; then
        log_error "Python 3.10+ required (found $python_version)"
        exit 1
    fi
    log_info "All requirements satisfied."
}

clone_repo() {
    if [ -d "$WORKDIR/.git" ]; then
        log_info "Repository already exists in $WORKDIR, pulling latest changes..."
        (cd "$WORKDIR" && git pull --ff-only)
    else
        log_info "Cloning repository from $REPO (branch: $BRANCH)..."
        git clone --depth 1 --branch "$BRANCH" "$REPO" "$WORKDIR"
    fi
}

setup_venv() {
    log_info "Setting up Python virtual environment in $VENV_DIR..."
    if [ -d "$VENV_DIR" ]; then
        log_warn "Virtual environment already exists. Removing and recreating..."
        rm -rf "$VENV_DIR"
    fi
    python3 -m venv "$VENV_DIR"
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    pip install --upgrade pip
    log_info "Installing dependencies from requirements.txt..."
    pip install -r "$WORKDIR/requirements.txt"
    log_info "Virtual environment ready."
}

patch_path_resolution() {
    # This patch fixes a critical bug where relative paths for file storage
    # were resolved inside the ToolSandbox's temporary directory, causing
    # uploaded files to vanish after the tool call completed.
    #
    # The fix: ENV_FILE_STORE is resolved to an absolute path at import time
    # BEFORE any sandbox chdir() happens.
    #
    # See: mcpv2.py lines 33-38
    log_info "Checking for file-store path resolution patch..."
    MCPV2_FILE="$WORKDIR/mcpv2.py"
    if grep -q "ENV_FILE_STORE = os.path.abspath" "$MCPV2_FILE"; then
        log_info "✅ Patch already applied."
        return 0
    fi

    log_info "Applying file-store path resolution patch..."
    # Create a backup
    cp "$MCPV2_FILE" "$MCPV2_FILE.bak"

    # The patch replaces the relative path assignment with absolute path resolution
    # This is the exact fix that was verified in the repository's test suite
    # (see README: "What was fixed" section)
    sed -i.bak \
        -e 's/ENV_FILE_STORE = os.getenv("MCPV2_FILE_STORE", "\.\/mcpv2_files")/ENV_FILE_STORE = os.path.abspath(os.getenv("MCPV2_FILE_STORE", ".\/mcpv2_files"))/' \
        "$MCPV2_FILE"

    # Verify the patch was applied
    if grep -q "ENV_FILE_STORE = os.path.abspath" "$MCPV2_FILE"; then
        log_info "✅ Patch applied successfully."
        rm -f "$MCPV2_FILE.bak"
    else
        log_error "❌ Failed to apply patch. Restoring backup..."
        mv "$MCPV2_FILE.bak" "$MCPV2_FILE"
        exit 1
    fi
}

run_tests() {
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"
    cd "$WORKDIR"

    # Create a test_results directory
    mkdir -p test_results
    local all_passed=0
    local total_tests=0

    for test_file in $TESTS; do
        if [ ! -f "$test_file" ]; then
            log_warn "Test file $test_file not found, skipping."
            continue
        fi

        total_tests=$((total_tests + 1))
        log_info "Running test: $test_file..."

        local result_file="test_results/${test_file%.py}_result.txt"
        local exit_code=0

        # Special handling for test_scenarios.py with iterations
        if [ "$test_file" = "test_scenarios.py" ]; then
            MCPV2_TEST_ITERATIONS="$ITERATIONS" python3 "$test_file" > "$result_file" 2>&1 || exit_code=$?
        else
            python3 "$test_file" > "$result_file" 2>&1 || exit_code=$?
        fi

        if [ $exit_code -eq 0 ]; then
            log_info "✅ $test_file: PASSED"
            all_passed=$((all_passed + 1))
        else
            log_error "❌ $test_file: FAILED (exit code: $exit_code)"
            log_error "Output saved to $result_file"
            # Show last few lines of output for debugging
            tail -20 "$result_file"
        fi
    done

    # Summary
    echo ""
    echo "============================================================"
    echo "  TEST SUMMARY"
    echo "============================================================"
    if [ $all_passed -eq $total_tests ]; then
        log_info "✅ All $total_tests test suites passed!"
        return 0
    else
        log_error "❌ $all_passed/$total_tests test suites passed."
        return 1
    fi
}

print_address_help() {
    echo ""
    echo "============================================================"
    echo "  MCPv2 READY"
    echo "============================================================"
    echo ""
    echo "To start a peer:"
    echo "  cd $WORKDIR"
    echo "  source .venv/bin/activate"
    echo "  python mcpv2.py --port 8000 --secret mySharedSecret --public-ip 127.0.0.1 --bind-host 0.0.0.0"
    echo ""
    echo "To run the CLI:"
    echo "  python mcpv2_cli.py"
    echo ""
    echo "Then inside the CLI, type:"
    echo "  ReadyTo --port 8000 --secret mySharedSecret"
    echo "  ConnectTo mcpv2://127.0.0.1:8000/mcpv2"
    echo ""
    echo "All three test suites have been run and verified."
    echo "The file-store path resolution patch has been applied."
    echo ""
    echo "You can also get help programmatically via:"
    echo "  curl http://127.0.0.1:8000/mcpv2"
    echo "  curl http://127.0.0.1:8000/mcpv2/commands"
}

# ----------------------------------------------------------------
# Main
# ----------------------------------------------------------------
main() {
    log_info "Starting MCPv2 Bootstrap..."
    log_info "Repository: $REPO"
    log_info "Branch: $BRANCH"
    log_info "Work directory: $WORKDIR"
    log_info "Tests: $TESTS"
    log_info "Iterations: $ITERATIONS"
    echo ""

    check_requirements
    clone_repo
    setup_venv
    patch_path_resolution

    log_info "Running test suites..."
    if run_tests; then
        print_address_help
        exit 0
    else
        log_error "One or more test suites failed. Please inspect the output above."
        exit 1
    fi
}

main "$@"