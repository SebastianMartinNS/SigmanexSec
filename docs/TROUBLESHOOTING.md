# SAP-Pentest — Operator troubleshooting

> Common failures, what they look like, and how to recover. Pair this
> with [`DEPLOYMENT.md`](DEPLOYMENT.md) (production setup) and
> [`IR_RUNBOOK.md`](IR_RUNBOOK.md) (incident response — breaches,
> credential rotation, audit-log compromise).

## Quick reference

| Symptom | Most likely cause | First action |
|---------|-------------------|--------------|
| Dashboard returns 503 on every API call | `SAP_DASHBOARD_USER` / `SAP_DASHBOARD_PASS` not set | Set them in `.env`, restart. |
| `/readyz` returns 503 with `session_db: missing` | `SESSION_DB_PATH` points at a non-existent file | Create the directory; the dashboard creates the file on first write. |
| `/readyz` returns 503 with `audit_log_dir.ok=false` | The audit log directory is not writable by the dashboard user | `chown sap:sap` the directory; check `chmod`. |
| `/readyz` returns 503 with `sudo_broker_socket.ok=false` | Broker daemon is not running but `SAP_SUDO_BROKER_ENABLED=1` is set | Start the broker (`sap-sudo-broker.service`) or unset the env var. |
| LLM chat hangs forever, no tokens stream | llama.cpp on port 8080 not reachable, or `SAP_PROMPT_TOKEN_BUDGET` overflow | See §1 and §2 below. |
| Tool call returns `ScopeViolation` | Target is not in the engagement scope (or DNS resolution failed) | Check `assert_in_scope` logs in `logs/audit.jsonl`; add the target via the engagement editor. |
| `pip install --require-hashes` complains about transitive dep | Lockfile drifted from `pyproject.toml` | Re-generate via `bash scripts/lock_deps.sh`, commit the diff. |

## 1. LLM stack failures

### Symptom: llama.cpp not reachable on port 8080

```text
[orch] anthropic_compatible: connection refused 127.0.0.1:8080
```

Steps:

```bash
systemctl status sap-llama
journalctl -u sap-llama -n 200 --no-pager
ss -tlnp | grep 8080
```

If the binary segfaults at startup, you almost certainly bumped the
`llama.cpp` submodule without re-applying patches:

```bash
cd /var/lib/sap/pentest-workspace
bash scripts/apply_llamacpp_patches.sh   # idempotent
cd llama.cpp && cmake --build build -j
systemctl restart sap-llama
```

### Symptom: `MCP error -32001` / "Mcp-Session-Id not found"

The browser cached a stale MCP session id after a server restart. The
shipped `mcp_http_runner.py` rewrites the broken 400 into a 404 so the
WebUI auto-heals. If you see this persistently, you are likely running
a forked runner without the patch.

```bash
grep -n _wrap_session_404 mcp_http_runner.py
```

If the function is absent, re-pull from upstream.

### Symptom: prompt budget exceeded

```text
[orch] _prompt_budget_guard: prompt over budget after pruning (token_count=234112 > 170000)
```

Either the engagement has accumulated too many tool calls (long-running
loop) or `SAP_PROMPT_TOKEN_BUDGET` is set lower than the model's
`n_ctx_slot`. Raise the budget cautiously:

```bash
export SAP_PROMPT_TOKEN_BUDGET=190000    # comfortably below the 200 704 slot
```

If the loop is genuinely stuck in repetition, abort and inspect the
`repetition` audit events.

## 2. MCP server failures

### Symptom: only some MCP servers visible to the WebUI

```bash
sudo -iu sap systemctl status 'sap-mcp@*'
```

Each unit is a templated service. Restart the failing one:

```bash
sudo systemctl restart sap-mcp@osint.service
```

Then check its log: `journalctl -u sap-mcp@osint --since '10 minutes ago'`.

### Symptom: tool output truncated unexpectedly

The MCP response shaper hard-caps every reply at `SAP_MCP_HARD_CAP_BYTES`
(default 32 KB). Truncated responses include `truncation_enforced: true`
and an `output_ref` pointing at the spill-to-disk file in
`runs/<run_id>/calls/<call_id>.jsonl`. Use the `read_tool_output_*`
recall handler with `mode=full` (still capped at
`SAP_MCP_RECALL_CAP_BYTES`, default 64 KB) to page through the rest.

## 3. Dashboard / auth

### Symptom: 429 "rate limit exceeded" hitting `/healthz`

Should not happen — `/healthz` and `/readyz` are exempt from the rate
limiter as of v2.2. If you see this, you are likely running an older
build. Verify:

```bash
grep -A2 '_SKIP_PREFIXES' sap_dashboard/backend/app.py
```

The list must contain `/healthz` and `/readyz`.

### Symptom: WebSocket disconnects every 60 seconds

Typically a reverse-proxy timeout. Set `proxy_read_timeout 3600s` in
nginx (see [`DEPLOYMENT.md`](DEPLOYMENT.md) §4) or the equivalent in
your reverse proxy.

### Symptom: CSRF token missing or invalid (403)

The browser was issued a CSRF cookie at login but is sending mutating
requests (POST / PATCH / DELETE) without an `X-CSRF-Token` header.
Inspect the dashboard JS console — vendor bundles must read the
`sap_csrf` cookie and echo it on every state-changing fetch.

## 4. Audit chain

### Symptom: `core.audit_log verify` reports corruption

```text
chain broken at line 1234: hash mismatch
```

Stop the platform immediately:

```bash
sudo systemctl stop sap-dashboard sap-mcp@* sap-llama sap-sudo-broker
```

The chain stored locally has been tampered with. Two paths forward:

1. If you operate an external sink (recommended), the SIEM / WORM copy
   is the authoritative record. Open a security incident, escalate,
   compare local vs. remote and identify the divergence point.
2. If you do not, the chain is unreliable from `line 1234` onward;
   archive the broken file out-of-band and start a fresh chain (the
   audit module writes a `chain_migration` event when it detects a
   reset).

See `IR_RUNBOOK.md` for the full incident handling steps.

## 5. sudo broker

### Symptom: privileged tool fails with `sudo_broker: SO_PEERCRED check failed`

The broker socket lives at `$XDG_RUNTIME_DIR/sap_sudo_<uid>.sock` and
requires the client UID to match the broker UID. If you start the
dashboard as `sap` but the broker as `root`, every request is rejected.

Use the systemd units in `deploy/systemd/`; they enforce a single user.

### Symptom: broker locks out after too many failed sudo unlocks

```text
[sudo_broker] lockout: 10 consecutive failures; retry after 900s
```

A lockout is the intended response to credential probing. Wait the
lockout window or, if you are certain it is legitimate, restart the
broker (this resets the counter but writes a `sudo_lockout_reset` audit
event so reviewers see what happened).

## 6. Installation / packaging

### Symptom: `sap-pentest: command not found` after install

The console script is generated by setuptools from `pyproject.toml`'s
`[project.scripts]`. Verify:

```bash
pip show sap-pentest | head -10
which sap-pentest
ls .venv/bin/sap-*
```

If the script is missing, re-install with `pip install -e .` from the
repo root. If using a system Python (not recommended), ensure
`~/.local/bin` is on `PATH`.

### Symptom: `pip install` pulls 600 MB of torch

You requested the `[ml]` extra (or installed before the v2.2 reshape).
The default install ships without `tiktoken` / `sentence-transformers`
because their fallbacks in `core/memory/{tokens,embeddings}.py` work
without them. To install with the heavy ML deps explicitly:

```bash
pip install 'sap-pentest[ml]'
```

## 7. Logs and observability

Default operational logs land in `./logs/` and are rotated by
`core/storage_gc._rotate_logs` (`SAP_LOG_ROTATE_SIZE_MB`,
`SAP_LOG_ROTATE_AGE_DAYS`, `SAP_LOG_ROTATE_KEEP`). The audit log
rotates independently inside `core/audit_log.py` to preserve the
hash chain.

To stream all logs at once:

```bash
bash monitor_all.sh
```

To enable JSON logging (recommended in containers / systemd):

```bash
export SAP_LOG_FORMAT=json
export SAP_LOG_LEVEL=INFO
```

Every dashboard request emits a `correlation_id` and echoes it back via
`X-Correlation-Id`. Use it to thread a request through dashboard,
orchestrator, and MCP logs.

## 8. When to escalate

* Audit chain verification fails → `IR_RUNBOOK.md` Tier 1.
* sudo broker memory dump observed → rotate the operator sudo password
  AND any credentials it could decrypt; rebuild the host.
* External sink confirms an action that does NOT appear in the local
  audit chain → presumed tamper. See `IR_RUNBOOK.md` Tier 1.

Report security issues via the channel listed in
[`SECURITY.md`](../SECURITY.md).
