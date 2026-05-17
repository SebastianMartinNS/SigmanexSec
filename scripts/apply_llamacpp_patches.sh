#!/usr/bin/env bash
# Apply the nine SAP-Pentest patches to the vendored llama.cpp submodule.
# Run after `git submodule update --init --recursive`.
#
# Idempotent: re-running on a clean tree re-applies; on an already-patched
# tree, `git apply --check` will skip with a clear error.
#
# Flags:
#   --check    Dry-run: verify every patch applies cleanly (or is already
#              applied) WITHOUT mutating the tree. Exits 0 on success,
#              non-zero on the first patch that does not apply. Used by
#              .github/workflows/ci.yml on submodule / patches changes.
set -euo pipefail

CHECK_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    -h|--help)
      sed -n '1,/^set -euo/p' "$0" | sed 's/^# \?//'
      exit 0
      ;;
    *)
      echo "unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LLAMA_DIR="$REPO_ROOT/llama.cpp"
PATCH_DIR="$REPO_ROOT/patches/llama.cpp"
PINNED_COMMIT="0beb8db3a0037b51f8247ac657b7655ab68fa9f0"

if [[ ! -e "$LLAMA_DIR/.git" ]]; then
  echo "ERROR: $LLAMA_DIR is not a git checkout." >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

current="$(git -C "$LLAMA_DIR" rev-parse HEAD)"
if [[ "$current" != "$PINNED_COMMIT" ]]; then
  echo "WARNING: llama.cpp HEAD is $current, expected $PINNED_COMMIT." >&2
  echo "         Patches may fail to apply against a different base." >&2
fi

shopt -s nullglob
patches=("$PATCH_DIR"/*.patch)
if [[ ${#patches[@]} -eq 0 ]]; then
  echo "ERROR: no patches found in $PATCH_DIR" >&2
  exit 1
fi

cd "$LLAMA_DIR"
for p in "${patches[@]}"; do
  name="$(basename "$p")"
  if git apply --check "$p" 2>/dev/null; then
    if (( CHECK_ONLY )); then
      echo "ok: $name would apply cleanly"
    else
      echo "applying $name"
      git apply "$p"
    fi
  elif git apply --check --reverse "$p" 2>/dev/null; then
    echo "skipping $name (already applied)"
  else
    echo "ERROR: $name does not apply cleanly. Inspect with:" >&2
    echo "       git -C $LLAMA_DIR apply --check $p" >&2
    exit 2
  fi
done

if (( CHECK_ONLY )); then
  echo
  echo "Dry-run complete: every patch applies cleanly against $current."
  exit 0
fi

echo
echo "All patches in sync. Now rebuild the WebUI bundle and llama-server:"
echo "  cd $LLAMA_DIR/tools/server/webui && node node_modules/.bin/vite build && bash scripts/post-build.sh"
echo "  cd $LLAMA_DIR && cmake -B build -DGGML_CUDA=ON -DLLAMA_BUILD_SERVER=ON && cmake --build build --config Release -j\$(nproc)"
