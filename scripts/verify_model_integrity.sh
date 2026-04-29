#!/usr/bin/env bash
# scripts/verify_model_integrity.sh — P1.8 hardening
#
# Verifies the SHA256 of every GGUF model listed in `models.sha256` against
# the file on disk. Used by `start_llm.sh` to refuse loading a tampered model.
#
# File format (one entry per line, lines starting with `#` ignored):
#     <sha256>  <absolute_or_relative_path>
#
# Exit codes:
#   0 — every listed file matches.
#   1 — at least one file mismatches (or is missing). The offending path is
#       printed to stderr.
#   2 — manifest file is missing (treated as soft-fail unless STRICT=1).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST="${MODELS_SHA256:-${ROOT}/models.sha256}"
STRICT="${STRICT:-0}"

if [[ ! -f "$MANIFEST" ]]; then
    echo "[verify_model] manifest not found: $MANIFEST" >&2
    if [[ "$STRICT" == "1" ]]; then
        exit 2
    fi
    echo "[verify_model] STRICT=0 — skipping (set STRICT=1 to enforce)" >&2
    exit 0
fi

fail=0
while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim leading/trailing whitespace.
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue

    expected="$(awk '{print $1}' <<<"$line")"
    path="$(awk '{$1=""; print substr($0,2)}' <<<"$line")"
    [[ -z "$expected" || -z "$path" ]] && continue

    if [[ ! -f "$path" ]]; then
        echo "[verify_model] MISSING: $path" >&2
        fail=1
        continue
    fi

    actual="$(sha256sum -- "$path" | awk '{print $1}')"
    if [[ "$actual" != "$expected" ]]; then
        echo "[verify_model] MISMATCH: $path" >&2
        echo "                  expected $expected" >&2
        echo "                  got      $actual"   >&2
        fail=1
    else
        echo "[verify_model] OK: $path"
    fi
done < "$MANIFEST"

exit "$fail"
