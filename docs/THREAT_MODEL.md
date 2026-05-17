# SAP-Pentest — Threat Model

> Scope: SAP-Pentest **v2.3**. Updates when a major architectural change
> lands (e.g. multi-tenant in v2.4, plugin loader in v2.4, container
> distribution in v3.0). Reviewers — please file issues against this
> document when you see a control that does not match code.

## 1. Methodology

STRIDE (Spoofing, Tampering, Repudiation, Information disclosure, Denial
of service, Elevation of privilege) applied per trust boundary. For each
trust boundary we enumerate the assets crossing it, the threats most
likely to materialise, and the controls already shipping in v2.3 that
mitigate them. Items that are *known gaps* are called out explicitly so a
reader knows what the platform does **not** defend against.

## 2. Assets

| Asset | Sensitivity | Persistence |
|---|---|---|
| Operator credentials (login pwd, sudo pwd) | **critical** | Argon2id at rest in `.env`; sudo pwd ephemeral, mlock'd in sudo broker |
| Engagement scope (CIDRs, domains, identity targets) | high | `sessions/assessments.db` (sqlite) |
| Findings & credentials harvested during the run | high | `sessions/assessments.db` |
| Audit chain (`logs/audit.jsonl`) | **critical** | append-only, BLAKE2b chained, optional external sink |
| Tool output (`runs/<run_id>/calls/*.jsonl`) | medium-high (may contain PII / creds) | local disk + redacted view sent to LLM |
| LLM session secret (`$XDG_STATE_HOME/sap/session.key`) | critical | local file 0600 |
| llama.cpp model weights | low (publicly downloadable, pinned by SHA256) | `llama.cpp/models/*.gguf` |
| Source code & release artefacts | medium (integrity matters) | GitHub repository + signed releases |

## 3. Trust boundaries (overview)

```
  ┌────────────┐ TB1 ┌────────────┐ TB2 ┌──────────────┐ TB3 ┌─────────┐
  │  Operator  │────►│  Dashboard │────►│ Orchestrator │────►│   LLM   │
  │ (browser)  │     │ (FastAPI)  │     │              │     │ runtime │
  └────────────┘     └─────┬──────┘     └──────┬───────┘     └─────────┘
                           │                   │ TB4
                           │                   ▼
                           │            ┌──────────────┐
                           │            │  MCP server  │
                           │            └──────┬───────┘
                           │                   │ TB5
                           │                   ▼
                           │            ┌──────────────┐ TB6 ┌──────────────┐
                           └──────────► │ ToolExecutor │────►│  sandbox + │ TB7
                                        │ (chokepoint) │     │   tool       │────► target estate
                                        └──────────────┘     └──────────────┘
```

* **TB1** Operator ↔ Dashboard (HTTP/HTTPS, browser ↔ FastAPI)
* **TB2** Dashboard ↔ Orchestrator (in-process; conceptual boundary)
* **TB3** Orchestrator ↔ LLM runtime (HTTP localhost, OR opt-in external API)
* **TB4** Orchestrator ↔ MCP server (MCP stdio/HTTP, local-only)
* **TB5** MCP server ↔ ToolExecutor (in-process)
* **TB6** ToolExecutor ↔ sandboxed tool (subprocess + bwrap user-ns)
* **TB7** Sandboxed tool ↔ target estate (network egress to authorised hosts only)

The four immutable security **chokepoints** sit astride these
boundaries and are not duplicated anywhere else:

| Chokepoint | File | Crossed at |
|---|---|---|
| Scope validation | `core/scope_validator.py` | TB5 (every ToolExecutor.run) |
| Tool execution gate | `core/executor.ToolExecutor.run` (line 343) | TB5, TB6 |
| Audit chain | `core/audit_log.py` (BLAKE2b-256) | every TB except TB7 |
| LLM I/O sanitisation | `core/llm_io_sanitizer.py` | TB3 |

## 4. STRIDE per trust boundary

### TB1 — Operator ↔ Dashboard (HTTPS, browser ↔ FastAPI)

| STRIDE | Threat | Controls (v2.3) | Residual |
|---|---|---|---|
| **S** Spoofing | Stolen session cookie reused by attacker | HttpOnly + Secure + SameSite=strict; idle window 30 min; absolute cap 8 h; `iat` re-checked on every request | Token theft via local malware on operator's box is out of scope |
| **T** Tampering | Forged request modifies state | Per-install HMAC key (`SAP_SESSION_SECRET`, 0600); itsdangerous TimestampSigner; CSRF double-submit on every state-changing method | None significant |
| **R** Repudiation | Operator denies action | Every authenticated action lands in BLAKE2b-chained audit (`auth.login`, `tool_execute`, `engagement_*`, `gdpr_*`) | Off-host sink recommended for forensic trust |
| **I** Info disclosure | Brute-force username enumeration via login error timing | `auth.cred.plaintext.deprecated` events; Argon2id constant-time verify; rate-limited `/api/auth/login` (5 fails / 60 s → 900 s lockout) | Login-timing side channel against viable usernames not actively measured |
| **D** DoS | Operator's source IP fills audit log | `_RateLimitMiddleware` 30 anon / 240 auth req/min; `/healthz` /`/readyz` exempt; per-IP WS cap | A coordinated multi-IP attack still exhausts the anon bucket |
| **E** Elevation | Viewer escalates to admin | `require_role` on every route (matrix `viewer/operator/admin`); test_p2_rbac_enforcement validates introspection | SSO group→role mapping (v2.4) introduces new attack surface |

### TB2 — Dashboard ↔ Orchestrator (in-process)

Logically, the dashboard and the orchestrator share the same Python
runtime; there is no kernel boundary between them. We treat this as
"fail-shared": any compromise of the dashboard process is by definition
a compromise of the orchestrator process. The only guard is **lifecycle
hygiene**:

* `harden_process()` (`core/process_hardening.py`) calls `mlockall()` so
  paged-out secrets cannot land on disk.
* `MemoryDenyWriteExecute=yes` in the shipped systemd units denies
  W^X pages so a memory-corruption bug cannot trivially gain RCE.
* Both `dashboard` and `orchestrator` processes drop capabilities to
  `CapabilityBoundingSet=` (empty) when run under systemd.

### TB3 — Orchestrator ↔ LLM runtime

| STRIDE | Threat | Controls (v2.3) | Residual |
|---|---|---|---|
| **S** Spoofing | Local-LLM endpoint impersonated by another process listening on 8080 | Listen-on-127.0.0.1 only; firewalled in systemd unit; loop-back binding documented | An attacker with local code-exec can still rebind 8080 |
| **T** Tampering | Tool result tampered before reaching the model | All tool results pass through `core.llm_io_sanitizer.sanitize_tool_output` (control-char strip, regex secret redaction, NFC normalisation, `<<<TOOL_OUTPUT>>>` fencing) | A heuristic bypass on the regex catalogue is possible — the redaction is best-effort, not formally complete |
| **R** Repudiation | Off-host LLM (OpenAI/Anthropic) call not logged | External-LLM calls emit `llm.external.optin` audit events; opt-in must be explicit per engagement (Fase 3) | v2.3 still supports the legacy paths without per-engagement opt-in |
| **I** Info disclosure | Tool output containing secrets/PII reaches an external LLM | Sanitiser strips AWS, GH PAT, JWT, Bearer tokens, plaintext "password=" patterns, RFC1918 + loopback IPs; opt-in required for any external endpoint | Custom secret formats (industry-specific tokens) are not in the regex catalogue |
| **D** DoS | LLM emits a tool-call loop that exhausts the prompt budget | Pre-flight guard `Orchestrator._prompt_budget_guard` truncates and aborts above `SAP_PROMPT_TOKEN_BUDGET` (170 000); `RepetitionHandler` detects fuzzy-hash loops and pivots | A bug in the guard could still let a runaway loop produce many MCP calls before tripping |
| **E** Elevation | Prompt injection from tool output convinces the model to abuse another tool | Indirect-prompt-injection fences `<<<TOOL_OUTPUT name=... call_id=...>>> ... <<<END>>>` plus a system-prompt rule that anything inside the fence is **data, not instruction** | A determined adversary can still craft attacker-controlled text that bypasses the heuristic |

### TB4 — Orchestrator ↔ MCP server (local stdio/HTTP)

| STRIDE | Threat | Controls (v2.3) | Residual |
|---|---|---|---|
| **S** Spoofing | A rogue process binds to one of the MCP ports (9001–9006) | systemd unit pins listening UID + binds 127.0.0.1; mcp_http_runner emits a startup banner only the legitimate process writes; orchestrator caches the per-process URI | A local attacker who can spawn arbitrary listeners on loopback wins before the legitimate broker starts |
| **T** Tampering | MCP response shape mutated mid-flight | All MCP responses go through `mcp_servers/_response.build_tool_response` which validates shape and enforces `SAP_MCP_HARD_CAP_BYTES` (default 32 KB); the orchestrator clamps again on receipt | Replay attacks on idempotent reads are not detected — they have no harm-bearing effect |
| **R** Repudiation | An MCP server denies a call was made | Both pre- and post-execution audit entries in `core/audit_log` |
| **I** Info disclosure | An MCP server leaks data from another engagement's run | The executor is constructed per process and scoped per call; `core/tool_output_store` keys on `(run_id, call_id)` | Single-tenant assumption — multi-tenant isolation is v2.4 |
| **D** DoS | A single huge tool output blocks the MCP server | Hard cap `SAP_MCP_HARD_CAP_BYTES` + spill-to-disk via `tool_output_store`; the orchestrator's truncation is the secondary cap | Spill-to-disk fills disk if `core/storage_gc` is disabled |
| **E** Elevation | An MCP server crashes and a less-trusted handler answers in its place | One systemd unit per MCP server with `Restart=on-failure` + `NoNewPrivileges` | A flapping unit will trip the systemd restart limiter and stop |

### TB5 — MCP server ↔ ToolExecutor (in-process)

The MCP server hands every external command to `ToolExecutor.run` (the
chokepoint). The MCP framing has no security purpose here; it just
adapts the JSON to the executor signature. Key controls:

* `_check_tool` validates the binary against the allowlist (`config.yaml`
  + `parrot_tools.yaml` + `executor.allowed_tools_blocklist`).
* `_check_args` checks every arg against compiled blocklist patterns
  (`executor.blocked_arg_patterns`) — defeats `;`, `&&`, `\``, `$(...)`
  and shell-metacharacters.
* `assert_in_scope` / `assert_identity_in_scope` raise `ScopeViolation`
  if the target is not in the engagement scope (closed by default).
* Audit pre/post entries pair every fork with a `tool_complete` entry
  carrying exit code, durations, and bytes counters.

### TB6 — ToolExecutor ↔ sandboxed tool (subprocess + bwrap)

| STRIDE | Threat | Controls (v2.3) | Residual |
|---|---|---|---|
| **S** Spoofing | A side-loaded binary shadows the legitimate tool | `S607` is intentionally allowed (tools come from `PATH`); operator is expected to lock `PATH` via the systemd unit's `Environment=` | An attacker with write access to `/usr/local/bin` can shadow a tool |
| **T** Tampering | The tool mutates a system file it should not touch | bwrap profile (`recon`, `exploit`, `osint`, `blueteam`, `parrot`, `engagement`) mounts root read-only and offers a per-run RW `/work` only; v2.3 default is `SAP_SANDBOX=warn`, flipping to `on` in v2.4 | `warn` mode does not enforce; `on` enforcement landed but is gated by user-namespace availability |
| **R** Repudiation | Tool ran but no record | `audit_log.tool_complete` is written after `subprocess.wait()`; on TIMEOUT we emit a `[TIMEOUT]` marker | Sigkill before the audit-after write loses one audit event (rare) |
| **I** Info disclosure | Tool output leaks an operator secret | `redact_sudo` strips sudo password material before output reaches disk or LLM; `llm_io_sanitizer` re-runs on the redacted output | Non-sudo secrets in a custom format that does not match the regex catalogue still leak |
| **D** DoS | Tool emits unbounded stdout | `_persist_max_bytes` (default 64 MiB) on each stream; `_kill_on_overflow` SIGKILLs the process group when the cap is hit | An attacker can still consume the cap-worth of disk before SIGKILL fires |
| **E** Elevation | Tool requires sudo and the sandbox would strip the setuid bit | v2.3 limitation: sudo-required tools run **outside** the sandbox after the sudo broker returns the password. A privileged-sandbox proxy is on the v2.4 roadmap | Documented gap; mitigated by sudo_broker SO_PEERCRED + mlock |

### TB7 — Sandboxed tool ↔ target estate

| STRIDE | Threat | Controls (v2.3) | Residual |
|---|---|---|---|
| **S** Spoofing | DNS poisoning steers the tool to a target that is not really in scope | `_resolve_domain_ips` resolves at scope-check time and caches with TTL 5 min; out-of-scope IP that maps to an in-scope domain is allowed (documented as least-surprise) | A poisoned cache is an out-of-scope concern |
| **T** Tampering | Tool's response is altered upstream | TLS where applicable; otherwise the operator's network is trusted | Trusted-network assumption is a deployment responsibility |
| **R** Repudiation | Target denies the action took place | Audit chain on our side captures argv + exit code + bytes; the target's logs are out of scope |
| **I** Info disclosure | Target leaks data we did not authorise to view | Mitigated by scope validation — we never connect outside scope; `assert_identity_in_scope` hard-matches and rejects wildcards | None within the platform's control |
| **D** DoS | Tool overloads target unintentionally | Operator-set timeouts and `SAP_EXECUTOR_TIMEOUT`; tool-specific throttling lives in the descriptor (parrot_tools.yaml) |
| **E** Elevation | Tool succeeds at lateral movement that was not in the operator's intent | Scope chokepoint refuses out-of-scope hosts; sudo broker requires explicit unlock | Scope errors of declaration are a human-process failure |

## 5. Known gaps (v2.3)

1. **External LLM opt-in granularity** — v2.3 still allows operators to
   set `LLM_PROVIDER=openai` globally without per-engagement consent.
   v2.4 introduces the per-engagement opt-in with `llm.external.optin`
   audit events.
2. **Multi-tenant isolation** — v2.3 is single-tenant by design;
   `tenant_id` lands in v2.4 with a chain-rebuild migration.
3. **Sandbox enforcement default** — v2.3 ships `SAP_SANDBOX=warn` for
   one release of grace. v2.4 flips the default to `on` after the
   warning-mode telemetry confirms zero false positive on the shipped
   hardening suites.
4. **Sudo-required tool sandboxing** — sudo strips setuid inside a user
   namespace, so privileged tools currently run un-sandboxed after
   `sudo_broker` hands over the password. v2.4 will introduce a
   privileged-sandbox proxy.
5. **Custom-secret regex catalogue** — `llm_io_sanitizer` covers
   common token shapes (AWS, GH PAT, JWT, Bearer). Customer-specific
   secret formats (vendor API tokens, internal cookie names) must be
   declared via the planned `SAP_REDACT_PATTERNS` extension (v2.4).
6. **Operator-host integrity** — the platform trusts that the host
   running the dashboard is not compromised. mlock + W^X + systemd
   hardening reduce blast radius but do not eliminate the
   assumption.

## 6. Coordinated vulnerability disclosure

Reports of newly discovered weaknesses against any item in this
document — or against the controls in `core/{scope_validator,
executor, audit_log, llm_io_sanitizer, sandbox}.py` — should be sent
privately:

* Email: `security@sigmanex.net`
* PGP key: published in [`SECURITY.md`](../SECURITY.md) (fingerprint
  pinned).
* Disclosure window: **90 days** from acknowledged report. We aim to
  ship a fix or mitigation within 30 days; the remaining window is for
  downstream consumers to upgrade before public disclosure.

We will publish a coordinated advisory under the project's GitHub
Security Advisories tab once a fix is available, crediting the
reporter unless they request anonymity.

## 7. Maintenance

This document is owned by the project maintainer
(`adriansebastianmartin@gmail.com`) and reviewed at every major release
(v2.4, v3.0, etc.). Pull requests against this file are welcome —
please include a CVD-style writeup of any new threat you would like to
see modelled.
