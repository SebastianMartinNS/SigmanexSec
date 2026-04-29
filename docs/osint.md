# Person / Identity OSINT Reference

This document is the operator-facing reference for the **identity OSINT**
capability. For the architectural / engineering spec see
[PENTEST_AGENT_MCP_SPEC.md §22](../PENTEST_AGENT_MCP_SPEC.md).

---

## Overview

A dedicated MCP server (`mcp_servers/osint_server.py`, port **9006**)
isolates all PII-touching tools from the rest of the platform. The
isolation buys us:

- **Auditability** — every PII call is flagged (`details.pii=true`,
  `details.identity_kind=<kind>`) so it can be filtered or purged
  on demand (GDPR right-to-erasure).
- **Disable-ability** — an engagement without `osint_authorization_ref`
  cannot invoke any OSINT tool, even if the binaries are installed.
- **Hard-match scope** — the target value must be present in the
  matching engagement scope list. No DNS fallback, no wildcards.

```
Engagement
├── authorization_ref         ← infra (CIDR/domain/URL)
├── osint_authorization_ref   ← identity (PII)  ← REQUIRED for any osint_*
├── scope_emails: [...]
├── scope_usernames: [...]
├── scope_persons: [...]
└── scope_social_handles: [...]
```

---

## The 9 OSINT tools

All tools accept `engagement_id` as their first argument; the server
validates the engagement, checks scope, runs the binary under
`ToolExecutor`, and parses output.

> **Accuracy baselines** below are the empirical thresholds asserted in
> [tests/test_osint_live.py](../tests/test_osint_live.py). They are
> deliberately conservative to absorb upstream platform churn (rate-limits,
> site outages). Run `SAP_LIVE_OSINT=1 pytest tests/test_osint_live.py -v`
> to refresh them on your installation.

### 1. `sherlock_run`

Find an authorized username across ~400 social networks.

| Field | Value |
|---|---|
| Binary | `sherlock` |
| Install | `pipx install sherlock-project` |
| Input kind | username |
| Accuracy baseline | ≥3 platforms for `octocat` (GitHub always present) |

```jsonc
sherlock_run(
  engagement_id="ENG-001",
  username="alice",
  timeout=10
)
// → {"tool":"sherlock_run","target":"alice","target_kind":"username",
//    "accounts":[{"platform":"GitHub","url":"https://github.com/alice","confidence":"high"}, ...],
//    "exit_code":0, "command":"sherlock --print-found ...", ...}
```

### 2. `maigret_run`

Deep username OSINT (3000+ sites). Slower than sherlock.

| Field | Value |
|---|---|
| Binary | `maigret` |
| Install | `pipx install maigret` |
| Input kind | username |
| Accuracy baseline | ≥5 platforms for `octocat` |
| Note | marked `@pytest.mark.slow`; 15-30 min per run typical |

### 3. `holehe_run`

Discover SaaS accounts registered against an authorized email.

| Field | Value |
|---|---|
| Binary | `holehe` |
| Install | `pipx install holehe` |
| Input kind | email |
| Accuracy baseline | exit-code-only (rate-limited heavily) |

### 4. `h8mail_run`

Email breach hunting via free public sources (HIBP scraper, Scylla).

| Field | Value |
|---|---|
| Binary | `h8mail` |
| Install | `pipx install h8mail` |
| Input kind | email |
| Accuracy baseline | exit-code valid; 0 breaches is a legitimate result |
| Optional | `config_file=` for paid API keys (HIBP, Snusbase, ...) |

The `config_file` argument is sanitized: shell metacharacters
(`;|&$\`\n` + space) are rejected before reaching the executor.

### 5. `whatsmyname_run`

Username enumeration using the WhatsMyName social-account dataset.

| Field | Value |
|---|---|
| Binary | `whatsmyname` |
| Install | `pipx install whatsmyname` |
| Input kind | username |
| Accuracy baseline | ≥3 platforms for `octocat`, OR exit_code==0 |

### 6. `social_analyzer_run`

Search and analyze a username across social media (top-N sites).

| Field | Value |
|---|---|
| Binary | `social-analyzer` |
| Install | `pipx install social-analyzer` |
| Input kind | username |
| Accuracy baseline | exit_code==0; account count variable |

### 7. `ghunt_email`

Extract Google account intel (Gaia ID, profile photo, …) from an email.

| Field | Value |
|---|---|
| Binary | `ghunt` |
| Install | `pipx install ghunt` |
| Input kind | email |
| Accuracy baseline | skip-friendly (interactive setup required) |

**One-time setup (interactive):**

```bash
ghunt login
# Follow the prompts to capture cookies into ~/.malfrats/ghunt/
```

If the cookie store is missing, the response will include
`setup_required` with the verbatim instruction. The agent prompt
([agent/prompts/system_prompt.md](../agent/prompts/system_prompt.md))
forbids attempts to bypass this.

### 8. `recon_ng_batch`

Run recon-ng with a curated, **passive-only** module set against an
authorized target.

| Field | Value |
|---|---|
| Binary | `recon-ng` |
| Install | `apt install recon-ng` (Parrot OS default) |
| Input kind | `domain` (uses infra scope) **OR** `email` / `person` / `username` (identity scope) |
| Modules | comma-separated; module names validated with `^[a-zA-Z0-9_./-]+$` |

The `domain` mode is the only path that does NOT require
`osint_authorization_ref` — it reuses the existing infra scope. All
other kinds enforce the full identity gate.

### 9. `spiderfoot_batch`

Run a SpiderFoot CLI scan with a curated PASSIVE module set.

| Field | Value |
|---|---|
| Binary | `sf` (SpiderFoot CLI) |
| Install | `apt install spiderfoot` |
| Input kind | `domain` / `email` / `person` / `username` |
| Modules | comma-separated; names validated with `^[a-zA-Z0-9_]+$` |

Like `recon_ng_batch`, `domain` uses the infra scope; the other kinds
enforce the identity gate.

---

## GDPR & PII compliance

Every successful OSINT execution writes an audit entry shaped like:

```json
{
  "ts": "2026-04-27T10:42:18.123Z",
  "engagement_id": "ENG-001",
  "tool": "sherlock",
  "target": "alice",
  "details": {
    "command": "sherlock --print-found ...",
    "phase": "recon",
    "exit_code": 0,
    "pii": true,
    "identity_kind": "username"
  }
}
```

### Find every PII call for a subject

```bash
jq -c 'select(.details.pii==true and .target=="alice@example.com")' logs/audit.jsonl
```

### Erase PII trace for a subject (right-to-erasure)

```bash
# Build a redacted copy and atomically replace.
jq -c 'select(.details.pii != true or .target != "alice@example.com")' \
  logs/audit.jsonl > logs/audit.jsonl.tmp \
  && mv logs/audit.jsonl.tmp logs/audit.jsonl
```

> The platform does NOT auto-erase — destructive log mutation is left
> deliberate and operator-driven, with a paper trail.

---

## When **not** to run OSINT tools

Refuse to run, and surface a clear message instead, when any of these hold:

1. The engagement has no `osint_authorization_ref` set.
2. The target value is not in the matching scope list (`scope_emails`,
   `scope_usernames`, `scope_persons`, `scope_social_handles`).
3. The target is a private individual who has not signed the OSINT ROE
   (this cannot be enforced technically — it's an operator obligation).
4. The platform is being asked to aggregate findings across multiple
   subjects into a single profile without explicit operator instruction.

The agent system prompt
([agent/prompts/system_prompt.md](../agent/prompts/system_prompt.md))
encodes these rules; the server-side `osint_server.py` enforces 1 and 2
as hard errors.

---

## Live accuracy testing

The repository ships [tests/test_osint_live.py](../tests/test_osint_live.py)
— 11 tests that invoke the real binaries against the canary targets:

| Canary | Used for |
|---|---|
| `octocat` | username / handle / person |
| `octocat@github.com` | email |
| `example.com` (RFC 2606) | domain |

Run them on demand:

```bash
SAP_LIVE_OSINT=1 pytest tests/test_osint_live.py -m live -v
```

Each test skips cleanly if its binary or the network is missing. The
audit log is redirected into a per-test temp directory by the
`live_engagement` fixture, so live runs **do not pollute** the real
`logs/audit.jsonl` or `sessions/assessments.db`.

---

## Cross-references

- Engineering spec: [PENTEST_AGENT_MCP_SPEC.md §22](../PENTEST_AGENT_MCP_SPEC.md)
- Server source: [mcp_servers/osint_server.py](../mcp_servers/osint_server.py)
- Scope enforcement: [core/scope_validator.py](../core/scope_validator.py)
- Identity normalization: [core/target_validator.py](../core/target_validator.py)
- Audit format: [core/audit_log.py](../core/audit_log.py)

---

## Dual route — `osint_*` vs `parrot_tool_run`

OSINT tools can be invoked through **two** MCP surfaces. They share the
same scope/auth gate and the same audit semantics; the difference is
ergonomic.

| Route | When to use | Example |
|---|---|---|
| `osint_*` (port 9006) | Hand-rolled, parsed responses (`accounts`, `breaches`, `module_results` …). Preferred for the agent. | [sherlock_run](sherlock_run)(engagement_id=…, username="octocat") |
| `parrot_tool_run` (port 9005) | Generic catalogue dispatcher; required for tools defined only in `parrot_tools.yaml`. Shares the engagement's identity scope when `category=="osint"` or `pii=true`. | [parrot_tool_run](parrot_tool_run)(name="sherlock_run", args_json='{"username":"octocat"}') |

Both routes:

1. Require `osint_authorization_ref` to be set on the engagement.
2. Require the target to be present in the matching identity scope list.
3. Return a structured `{"error": "setup_required", "missing_binary": …,
   "install_cmd": …}` instead of `FileNotFoundError` when the binary is
   not on `PATH`. The agent must skip and continue.
4. Are serialized per engagement via an `asyncio.Lock` to make the
   shared `ToolExecutor._scope` mutation safe under concurrency.

### Catalogue filtering

`parrot_list_tools(category="osint")` defaults to `available_only=True`,
so the agent only sees tools whose binary is actually installed. Pass
`available_only=False` to inspect the full catalogue (useful for setup
diagnostics).

### Tool-call loop breaker

The orchestrator hashes `(tool_name, sorted(args))` with SHA1 and
aborts when the same call is repeated more than `_TOOL_LOOP_LIMIT`
times in a single run (default `3`, override via the env var of the
same name). The dashboard `/status` endpoint exposes the per-run
`tool_call_loop_detected` counter so loops are visible in real time.

### Auto-report hook

When the agent calls `set_phase(phase="reporting")` or
`complete_engagement`, the orchestrator automatically invokes
`generate_assessment_report(engagement_id, format_type="markdown")`
exactly once per engagement and surfaces the resulting `saved_to`
path in the chat transcript. The agent must **never** reproduce the
report inline — only quote the path.

### Shared-authorization warning

If `authorization_ref == osint_authorization_ref` (and both are
non-empty) the engagement model emits a stderr warning at creation
time. Infra and OSINT/PII activities normally rest on two distinct
ROE references; sharing the same string is almost always a copy-paste
mistake.

