#!/usr/bin/env bash
# lock_deps.sh — Regenerate requirements.lock and requirements-dev.lock from
# pyproject.toml so reproducible installs (`pip install --require-hashes -r
# requirements.lock`) stay aligned with the project's declared dependency set.
#
# Run this any time you add, remove, or bump a version in pyproject.toml.
# The resulting lockfiles MUST be committed alongside the pyproject.toml
# change so CI and downstream consumers see a single source of truth.
#
# Usage:
#   bash scripts/lock_deps.sh           # regenerate both lockfiles
#   bash scripts/lock_deps.sh --upgrade # also bump pinned transitive versions

set -euo pipefail

cd "$(dirname "$0")/.."

PIP_COMPILE=(python -m piptools compile
    --quiet
    --generate-hashes
    --resolver=backtracking
    --strip-extras
    --allow-unsafe
)

if [[ "${1:-}" == "--upgrade" ]]; then
    PIP_COMPILE+=(--upgrade)
fi

if ! python -c "import piptools" >/dev/null 2>&1; then
    echo "pip-tools is not installed in the active environment." >&2
    echo "Install with: pip install 'pip-tools>=7.4.0'" >&2
    exit 1
fi

echo "[lock_deps] Regenerating requirements.lock (runtime dependencies)…"
"${PIP_COMPILE[@]}" --output-file=requirements.lock pyproject.toml

echo "[lock_deps] Regenerating requirements-dev.lock (runtime + dev tooling)…"
"${PIP_COMPILE[@]}" --extra=dev --output-file=requirements-dev.lock pyproject.toml

echo "[lock_deps] Done. Diff the lockfiles before committing:"
echo "    git diff requirements.lock requirements-dev.lock"
