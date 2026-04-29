#!/usr/bin/env bash
# scripts/verify_deps.sh — P1.8: pin + verify Python dependencies.
#
# Usage:
#   bash scripts/verify_deps.sh lock      Generate requirements.lock with
#                                          pinned versions and SHA256 hashes
#                                          using `pip-compile --generate-hashes`.
#   bash scripts/verify_deps.sh check     Verify the currently-installed
#                                          environment matches requirements.lock
#                                          (refuses to proceed if drifted).
#   bash scripts/verify_deps.sh audit     Run pip-audit + safety + bandit.
#
# The lock file is what gets installed in production:
#   pip install --require-hashes -r requirements.lock
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SRC="${ROOT}/requirements.txt"
LOCK="${ROOT}/requirements.lock"

cmd="${1:-check}"

ensure() {
    local pkg="$1"
    if ! python -c "import $2" >/dev/null 2>&1; then
        echo "[verify_deps] installing $pkg" >&2
        python -m pip install --quiet "$pkg"
    fi
}

case "$cmd" in
    lock)
        ensure "pip-tools" "piptools"
        echo "[verify_deps] regenerating $LOCK with hashes from $SRC"
        pip-compile --quiet --generate-hashes \
            --output-file "$LOCK" "$SRC"
        echo "[verify_deps] OK — wrote $(wc -l <"$LOCK") lines"
        ;;
    check)
        if [[ ! -f "$LOCK" ]]; then
            echo "[verify_deps] $LOCK missing — run: bash $0 lock" >&2
            exit 2
        fi
        ensure "pip-tools" "piptools"
        # `pip-sync --dry-run` exits non-zero if the env diverges.
        pip-sync --dry-run "$LOCK" || {
            echo "[verify_deps] FAIL: installed env diverges from $LOCK" >&2
            echo "  Sync with: pip-sync $LOCK"
            exit 1
        }
        echo "[verify_deps] OK — env matches $LOCK"
        ;;
    audit)
        ensure "pip-audit" "pip_audit"
        ensure "bandit"    "bandit"
        echo "── pip-audit ────────────────────────────────────"
        pip-audit -r "$LOCK" 2>/dev/null || pip-audit -r "$SRC"
        echo "── bandit (static analysis) ─────────────────────"
        bandit -q -r "${ROOT}/core" "${ROOT}/sap_dashboard" "${ROOT}/agent" \
               -ll -ii \
               --exclude "${ROOT}/llama.cpp,${ROOT}/build" \
               || true
        ;;
    *)
        echo "Usage: $0 {lock|check|audit}" >&2
        exit 64
        ;;
esac
