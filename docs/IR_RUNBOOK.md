# Incident Response Runbook — SAP

Audience: SRE / SecOps on call. Reference under stress; keep concise.

## 1. Severity matrix

| Sev | Definition                                                           | Examples                                                                            | Initial response time |
|-----|----------------------------------------------------------------------|-------------------------------------------------------------------------------------|-----------------------|
| P0  | Confidentiality / integrity loss in production                       | Audit-log gap, exposed secret, RCE on dashboard, sudo-broker compromise             | 15 min                |
| P1  | Active exploitation attempt or auth bypass                           | Brute-force succeeded, CSRF token leak, MCP server escaping scope                   | 30 min                |
| P2  | Hardening regression without active exploitation                     | CSP weakened, mlock failed, TLS cert near expiry, rate-limit bypass                 | 4 h                   |
| P3  | Operational degradation                                              | One MCP unit crash-looping, dashboard 5xx burst, audit-sink unreachable             | 1 business day        |

## 2. Detect

Signals:
* `logs/audit.jsonl` chain break — run `python -m core.audit_log verify`.
* `journalctl -u sap-dashboard` reports 401 storm or `csp-violation` POSTs.
* External syslog sink (`SAP_AUDIT_SINK_SYSLOG`) shows a gap vs. local file.
* `systemd-analyze security sap-dashboard` regression below 1.5.

## 3. Contain

```bash
# Freeze the dashboard (keeps audit + state intact).
sudo systemctl stop sap-dashboard
# Block egress at the host firewall while triaging.
sudo nft add rule inet filter output oifname "eth0" drop comment "ir-freeze"
# Snapshot state for forensics — DO NOT mutate.
sudo cp -a /var/lib/sap   /var/backups/sap-ir-$(date +%s)
sudo cp -a /var/log/sap   /var/backups/sap-ir-$(date +%s)/log
sudo cp -a logs/audit.jsonl /var/backups/sap-ir-$(date +%s)/audit.jsonl
sudo cp -a logs/audit.jsonl.head /var/backups/sap-ir-$(date +%s)/audit.jsonl.head
```

If sudo-broker is suspected compromised, also:

```bash
sudo systemctl stop sap-sudo-broker
sudo passwd -l sap          # disable interactive escalation paths
```

## 4. Eradicate

1. Rotate every secret in `/etc/sap/secrets.env` (session signer, dashboard
   password hash, llama API key, sudo-broker shared secret).
2. Re-issue TLS certs (`certbot renew --force-renewal`) and pin the new
   fingerprint in monitoring.
3. Rebuild the container: `podman build --no-cache …` then
   `podman image prune -a` to remove the suspect image.
4. Wipe and recreate `/var/lib/sap` ONLY if integrity of state is in doubt
   — otherwise verify with the audit chain.
5. Reset RBAC by deleting `/var/lib/sap/rbac.db` and re-seeding.

## 5. Recover

1. Bring services up in order: `sap-llm` → `sap-mcp@*` → `sap-sudo-broker`
   → `sap-dashboard`.
2. Confirm the audit chain head matches the WORM mirror:
   `sha256sum /var/log/sap/audit.head /mnt/worm/audit.head`.
3. Smoke test: login, RBAC-restricted endpoint, write an audit event,
   verify it appears in the external syslog sink within 5 s.
4. Lift the egress block once green.

## 6. Lessons learned

Within 5 business days of closure:

* Open a `post-mortems/YYYYMMDD-<slug>.md` with timeline, root cause,
  detection gap, remediation, and a list of follow-ups linked to issues.
* Update this runbook with any new detection or containment shortcut.
* Add a regression test under `tests/test_p*_*.py` that would have
  triggered before the incident.

## 7. Contact tree

| Role             | Primary           | Backup            | Escalation |
|------------------|-------------------|-------------------|------------|
| IR commander     | secops oncall     | head of platform  | CISO       |
| Platform / SRE   | platform oncall   | sre lead          | CTO        |
| Legal / DPO      | dpo@sigmanex.net   | legal@sigmanex.net | GC         |

> Keep this file under version control. Any change MUST go through PR
> review by SecOps + Platform.
