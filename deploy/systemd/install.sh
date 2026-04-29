#!/usr/bin/env bash
# deploy/systemd/install.sh — install hardened SAP systemd units (P4.1).
#
# Idempotent. Requires root. Steps:
#   1. Create `sap` user/group with /var/lib/sap home (no shell login).
#   2. Lay out /opt/sap (code), /etc/sap (config + secrets), /var/lib/sap
#      (state), /var/log/sap (logs), /run/sap (runtime).
#   3. Copy unit files into /etc/systemd/system/.
#   4. systemd-analyze security each unit (informational, non-blocking).
#   5. systemctl daemon-reload + enable.
#
# Run from the repository root:
#     sudo bash deploy/systemd/install.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must be root" >&2; exit 1; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
UNITS_SRC="$REPO/deploy/systemd"

# 1) System user.
if ! id -u sap >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/sap --shell /usr/sbin/nologin sap
fi

# 2) Filesystem layout.
install -d -o root -g root -m 0755 /opt/sap
install -d -o root -g sap  -m 0750 /etc/sap
install -d -o sap  -g sap  -m 0700 /var/lib/sap
install -d -o sap  -g sap  -m 0700 /var/log/sap
install -d -o sap  -g sap  -m 0700 /run/sap

# Code: rsync the repo into /opt/sap (excluding state directories).
rsync -a --delete \
    --exclude='.git/' --exclude='logs/' --exclude='sessions/' \
    --exclude='runs/' --exclude='reports/' --exclude='__pycache__/' \
    --exclude='.venv/' \
    "$REPO/" /opt/sap/
chown -R root:root /opt/sap
chmod -R go-w /opt/sap

# 3) Units.
for unit in sap-llm.service sap-dashboard.service sap-sudo-broker.service sap-mcp@.service; do
    install -m 0644 "$UNITS_SRC/$unit" "/etc/systemd/system/$unit"
done

# 4) Security report (informational).
echo "──────────────── systemd-analyze security ────────────────"
for u in sap-llm sap-dashboard sap-sudo-broker; do
    if systemd-analyze security "$u.service" 2>/dev/null | tail -3; then
        :
    fi
done
echo "──────────────────────────────────────────────────────────"

# 5) Reload + enable.
systemctl daemon-reload
systemctl enable sap-sudo-broker.service sap-llm.service sap-dashboard.service
for s in recon exploit osint blueteam engagement parrot; do
    systemctl enable "sap-mcp@${s}.service"
done

echo "OK — units installed. Start with:  systemctl start sap-llm sap-dashboard"
