#!/usr/bin/env bash
# scripts/regen_vendor_sri.sh — re-pin SRI hashes in index.html (P3.2).
set -euo pipefail
cd "$(dirname "$0")/.."
HTML="sap_dashboard/frontend/index.html"
VEND="sap_dashboard/frontend/vendor"

[[ -d "$VEND" ]] || { echo "no vendor directory at $VEND" >&2; exit 1; }

python3 - "$HTML" "$VEND" <<'PY'
import base64, hashlib, re, sys
from pathlib import Path
html_path = Path(sys.argv[1])
vendor    = Path(sys.argv[2])
src = html_path.read_text(encoding="utf-8")
changed = 0
for f in sorted(vendor.iterdir()):
    if not f.is_file():
        continue
    sri = "sha256-" + base64.b64encode(hashlib.sha256(f.read_bytes()).digest()).decode()
    pat = re.compile(
        r'((?:href|src)="/vendor/' + re.escape(f.name) + r'"\s+integrity=")[^"]*(")',
        re.DOTALL,
    )
    new, n = pat.subn(lambda m: m.group(1) + sri + m.group(2), src, count=1)
    if n:
        if new != src:
            print(f"  pinned {f.name} -> {sri}")
            changed += 1
        src = new
    else:
        print(f"  [skip] {f.name} not referenced in {html_path}", file=sys.stderr)
html_path.write_text(src, encoding="utf-8")
print(f"OK — {changed} hash(es) updated in {html_path}")
PY
