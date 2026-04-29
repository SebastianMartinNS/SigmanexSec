#!/usr/bin/env bash
# scripts/inventory_parrot.sh
#
# Compares parrot_tools.yaml against the binaries actually installed on this
# host. Prints a JSON report on stdout (consumable by the dashboard) and a
# human summary on stderr.
#
# Usage:
#   bash scripts/inventory_parrot.sh                  # JSON report
#   bash scripts/inventory_parrot.sh --install-hint   # also print apt-install hints

set -euo pipefail
cd "$(dirname "$0")/.."

python3 - "$@" <<'PY'
import json, shutil, sys
sys.path.insert(0, '.')
from core.parrot_catalog import load_catalog, gap_report

cat = load_catalog()
report = gap_report()
report["details"] = []
for d in cat:
    bin_name = d.get("binary", d["name"])
    path = shutil.which(bin_name)
    report["details"].append({
        "name": d["name"],
        "binary": bin_name,
        "category": d.get("category"),
        "requires_sudo": bool(d.get("requires_sudo")),
        "path": path,
        "installed": bool(path),
    })

print(json.dumps(report, indent=2))

print(
    f"\n[inventory] {report['available_count']}/{report['total']} tools installed; "
    f"{report['missing_count']} missing.",
    file=sys.stderr,
)
if "--install-hint" in sys.argv and report["missing"]:
    print("[inventory] Install hint (Parrot/Debian):", file=sys.stderr)
    print("  sudo apt update && sudo apt install -y \\", file=sys.stderr)
    print("    " + " \\\n    ".join(sorted(set(
        d["binary"] for d in cat
        if d["name"] in report["missing"]
    ))), file=sys.stderr)
PY
