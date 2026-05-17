# SAP-Pentest — Sigmanex Security Assessment Platform

> **A [Sigmanex](https://www.sigmanex.net) open-source release.**
> Repository: <https://github.com/SigmanexSec/SigmanexSec>.
> SAP-Pentest is published as a public demonstration of the
> engineering, security and compliance practices we apply across the
> Sigmanex stack. It is the same control fabric — scope enforcement,
> tamper-evident audit, hardened runtime, GDPR-aware data handling —
> that we ship in our commercial deliverables, made available so that
> auditors, customers and the wider community can read, verify and
> reuse the code.

> **⚠️ Authorization is mandatory.** SAP-Pentest performs *active*
> security testing against infrastructure and identity targets. You
> MUST have explicit written authorization from the legitimate owner
> before creating an engagement. Unauthorized testing is illegal in
> virtually every jurisdiction. The platform refuses to act outside
> the declared scope and audit-logs every command. See
> [AUTHORIZATION.md](AUTHORIZATION.md) for the rules of engagement
> checklist.

SAP-Pentest is a self-hosted, agentic penetration testing platform.
A local large language model (the patched `llama.cpp` server bundled
under [`llama.cpp/`](llama.cpp/), driving Qwen3.5-class GGUF models)
orchestrates roughly one hundred and forty-five offensive Parrot OS
tools through six specialized **Model Context Protocol** servers.
Every tool invocation passes through a single audited choke point that
validates the target against the declared scope, runs the binary in a
bounded sandbox, sanitises secrets out of the output before it reaches
the model, and writes a BLAKE2b-chained entry to the audit journal
before any reply is returned to the operator.

> **You must build the bundled `llama.cpp` fork.** SAP-Pentest depends
> on nine local patches to `llama.cpp` (tool-call promotion from the
> reasoning channel, CORS proxy host:port handling, WebUI MCP
> defaults, JSON-mode HTTP transport, and more). Pulling stock
> `ggerganov/llama.cpp` will break tool calling and the embedded
> WebUI. Full inventory and build steps are in
> [LLAMACPP_FORK.md](LLAMACPP_FORK.md).

```
┌───────────────────────────┐         ┌──────────────────────────┐
│  Operator                 │ HTTP    │  Dashboard (FastAPI)     │
│  (CLI / web dashboard)    │◀───────▶│  http://127.0.0.1:8765   │
└───────────┬───────────────┘         └──────────┬───────────────┘
            │ orchestrator                       │
            ▼                                    ▼
┌───────────────────────────┐    ┌────────────────────────────────┐
│  llama.cpp server         │◀──▶│  6 × MCP servers (9001-9006)   │
│  (Qwen, port 8080)        │    │  engagement | recon | exploit  │
└───────────────────────────┘    │  blueteam | parrot | osint     │
                                  └──────────────┬─────────────────┘
                                                 ▼
                                       ┌───────────────────┐
                                       │  ToolExecutor     │
                                       │  (audit + scope)  │
                                       └─────────┬─────────┘
                                                 ▼
                                       Parrot OS binaries
```

---

## Quick start

For a step-by-step installation guide (system bootstrap, model download,
llama.cpp build, credentials, first login, troubleshooting) see
**[docs/INSTALL.md](docs/INSTALL.md)**. The condensed version:

```bash
# 1. Clone with the llama.cpp submodule
git clone --recursive https://github.com/SigmanexSec/SigmanexSec.git sap-pentest
cd sap-pentest

# 2. System bootstrap (NVIDIA GPU + kernel 6.17 + Parrot tools)
bash install_gpu.sh

# 3. Python dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 4. Apply the nine local llama.cpp patches and build llama-server
bash scripts/apply_llamacpp_patches.sh
# Then build (CUDA): see docs/INSTALL.md § 4 for the full cmake invocation.

# 5. Download a Qwen3.5-class GGUF into llama.cpp/models/
# Verify checksums against models.sha256 (see docs/INSTALL.md § 5).

# 6. Configure credentials (REQUIRED — dashboard refuses to start otherwise)
cp .env.example .env
# Edit .env and set at minimum:
#   SAP_DASHBOARD_USER, SAP_DASHBOARD_PASS, SAP_SESSION_SECRET
# Generate a session secret with:
#   python -c "import secrets; print(secrets.token_urlsafe(48))"

# 7. Start everything: LLM + 6 MCP servers + dashboard + sudo broker
bash start_all.sh

# 8. Open the dashboard and log in with the SAP_DASHBOARD_USER / SAP_DASHBOARD_PASS
#    you set in step 6.
xdg-open http://127.0.0.1:8765
```

Stop everything with `bash stop_all.sh`. Live status: `bash status_all.sh`.
Multi-pane log monitor: `bash monitor_all.sh`.

---

## System requirements

| Component | Minimum |
|---|---|
| OS | Parrot OS (or any Debian-based with `apt` + Parrot repos) |
| Kernel | 6.17 (NVIDIA 550 DKMS is broken on 6.19 — see [switch_to_kernel617.sh](switch_to_kernel617.sh)) |
| GPU | NVIDIA RTX 4060 8 GB+ (CPU-only fallback: `NGL=0 bash start_llm.sh server`) |
| RAM | 16 GB |
| Python | 3.11+ |
| Network | Required for OSINT live tests, optional for offline runs |

---

## Engagement workflow

```bash
# Interactive wizard — captures scope (CIDR/domain/URL + identity) and
# authorization references.
python cli.py engage

# Run the agent against an engagement
python cli.py run -e <engagement_id> -o "Find all vulnerabilities on 10.0.0.1"

# Inspect status / discovered hosts / findings
python cli.py status -e <engagement_id>

# List all engagements
python cli.py list
```

---

## MCP servers

The agent talks to six specialized MCP servers over HTTP/streamable transport:

| Port | Server | Responsibility |
|------|--------|----------------|
| 9001 | engagement | Create/list engagements; manage hosts/credentials/findings |
| 9002 | recon      | Network discovery, port/service scans, web fingerprint |
| 9003 | exploit    | SQLi/cmd-injection probes, brute force, kerberoast, secrets dump |
| 9004 | blueteam   | Hardening recommendations, sigma/firewall rule generators |
| 9005 | parrot     | Generic catalog runner (~145 tools via `parrot_tool_run`) |
| 9006 | **osint**  | Person / Identity OSINT — email, username, person, social handle (see below) |

Architecture detail: [PENTEST_AGENT_MCP_SPEC.md](PENTEST_AGENT_MCP_SPEC.md) §3.

---

## Person / Identity OSINT (identity-targeted reconnaissance)

A dedicated MCP server (`mcp_servers/osint_server.py`, port **9006**) exposes
9 tools that target **identity** (email, username, person, social handle)
rather than infrastructure. Hard rules enforced server-side:

1. The engagement **must** carry a non-empty `osint_authorization_ref`
   (separate from the infra `authorization_ref`).
2. The target **must** appear in the matching identity scope list
   (`scope_emails` / `scope_usernames` / `scope_persons` /
   `scope_social_handles`) — case-insensitive, normalized, **hard-match**.
   No DNS fallback, no wildcards, no soft-allow.
3. Every PII execution is audit-logged with `details.pii=true` and
   `details.identity_kind`, supporting GDPR right-to-erasure filtering.

Tools: `sherlock_run`, `maigret_run`, `holehe_run`, `h8mail_run`,
`whatsmyname_run`, `social_analyzer_run`, `ghunt_email`, `recon_ng_batch`,
`spiderfoot_batch`. Full reference: **[docs/osint.md](docs/osint.md)**.

Example engagement creation with identity scope:

```text
$ python cli.py engage
Engagement name: OSINT-self
Authorization document reference: ROE-2026-001
Scope CIDRs: <empty>
Scope domains: example.com
Scope emails: alice@example.com
Scope usernames: alice
OSINT authorization document reference: ROE-OSINT-2026-001
```

GDPR right-to-erasure query:

```bash
jq -c 'select(.details.pii==true and .target=="alice@example.com")' logs/audit.jsonl
```

---

## Testing

The repository ships three tiers of tests:

```bash
# Default — fast, offline, deterministic (~25 s, 402 tests).
pytest tests/

# Live OSINT — invokes real binaries against canary public targets.
# Skips per-test if a binary is missing or the network is unreachable.
SAP_LIVE_OSINT=1 pytest tests/test_osint_live.py -m live -v

# Lab end-to-end — requires an isolated lab CIDR (your responsibility).
PENTEST_LAB_CIDR=10.10.10.0/24 pytest -m lab

# Scenario-driven QA (nmap + dirb against a local stub HTTP server)
python scripts/qa_scenario.py
```

`live` and `lab` are excluded from the default run via
[pyproject.toml](pyproject.toml) (`addopts = "-m 'not live and not lab'"`).

Live OSINT canaries (kept stable across releases):
- username / handle / person → `octocat`
- email → `octocat@github.com`
- domain → `example.com`

---

## Security controls

The platform is built around a small number of choke points that every
operation has to pass through. These are the controls Sigmanex relies
on internally and that this open-source release exposes for review.

**Authentication and session management.** The dashboard refuses to
start unless `SAP_DASHBOARD_USER` and `SAP_DASHBOARD_PASS` (or the
multi-user `SAP_DASHBOARD_USERS` JSON directory) are present in the
environment; otherwise every API call returns HTTP 503. Credentials
are compared with `secrets.compare_digest` (constant time) against the
values kept in process memory — they are never written to disk by the
platform itself, so it is on the operator to keep `.env` permissions
tight (`chmod 600`) and outside of version control. After login, the
browser receives an `itsdangerous`-signed `sap_session` cookie marked
`HttpOnly`, `Secure`, `SameSite=Strict`, with a thirty-minute idle
window and an eight-hour absolute lifetime, signed with
`SAP_SESSION_SECRET`. State-changing requests require a double-submit
`X-CSRF-Token` header that is validated against a separate cookie.
Failed `/api/auth/login` and `/api/sudo/unlock` attempts are rate
limited per process.

**Role-based access control.** Three roles are defined in
[`sap_dashboard/backend/rbac.py`](sap_dashboard/backend/rbac.py):
*viewer* (read-only), *operator* (run engagements, request sudo, send
to interactive sessions) and *admin* (settings, GDPR purge, system
reset). Every state-changing route is annotated with a
`require_role(...)` dependency.

**Scope and target enforcement.** Every infrastructure target passes
through [`core/target_validator.py`](core/target_validator.py) for
syntactic validation and then through
[`core/scope_validator.py`](core/scope_validator.py) for membership
in the engagement's declared CIDRs, domains and URLs. Identity
targets (email, username, person, social handle) take a separate path
that requires a non-empty `osint_authorization_ref` and a hard,
case-insensitive normalised match against the identity scope lists.
There is no DNS fallback, no wildcard, no soft-allow.

**Single execution choke point.** Every binary launched by the agent
goes through [`core.executor.ToolExecutor.run`](core/executor.py),
which enforces the timeout, captures `stdout`/`stderr` into the
output store, redacts the LLM-bound copy via
[`core/llm_io_sanitizer.py`](core/llm_io_sanitizer.py) (AWS keys,
JWTs, RFC1918 addresses, common credential patterns) and writes the
audit entry. Direct `subprocess` calls in MCP server code are not
allowed and are caught in review.

**Tamper-evident audit journal.** Audit entries form a BLAKE2b-256
hash chain in [`logs/audit.jsonl`](logs/audit.jsonl), with the chain
head also written to `logs/audit.jsonl.head`. A verifier
(`python -m core.audit_log verify`) detects gaps and rewrites. An
optional external sink ([`core/audit_sink.py`](core/audit_sink.py))
mirrors the chain to syslog and a WORM volume so that on-host
tampering does not break the audit story.

**Privacy and right to erasure.** Tool calls that touch identity
targets set `pii=true` and `identity_kind` in the audit record so that
[`core/gdpr.py`](core/gdpr.py) and the GDPR purge tool can locate and
redact them. Reports go through the same sanitiser before they leave
`reports/`.

**Privileged actions.** [`core/sudo_broker.py`](core/sudo_broker.py)
runs as a small UNIX-socket daemon. It checks the connecting peer's
UID, accepts a one-shot password unlock from the dashboard, caches it
in a memory page that is `mlock`'d and zeroized after a TTL, and
brokers calls without ever exposing the password to the LLM context.

**Process and runtime hardening.** At startup the dashboard process
calls `mlockall` and the systemd units in
[`deploy/systemd/`](deploy/systemd/) apply
`MemoryDenyWriteExecute=yes`, `NoNewPrivileges=yes`,
`RestrictAddressFamilies=`, capability drops and a seccomp filter,
verified by `systemd-analyze security` in
[`scripts/check_hardening.sh`](scripts/check_hardening.sh).

**Web hardening.** A per-request CSP nonce is injected into
`script-src`, the frontend ships only vendored, SRI-pinned assets
(no CDN), `Trusted Types` is required in report-only mode, and HSTS
is enforced when served over TLS. The body-size limiter rejects
payloads above two megabytes by default.

**Rate limiting.** A sliding-window per-IP limiter
([`core/rate_limiter.py`](core/rate_limiter.py)) protects the
dashboard against brute-force and accidental request storms.

**Storage retention.** [`core/storage_gc.py`](core/storage_gc.py)
sweeps `runs/`, `sessions/` and `reports/` against the documented
retention policy.

**Supply chain.** Dependencies are pinned in `requirements.txt`, the
GitHub Actions workflow [`.github/workflows/security.yml`](.github/workflows/security.yml)
runs `pip-audit` and `bandit` on every push and pull request and on a
weekly cron, and the GGUF model is verified by SHA256 in
[`scripts/verify_model_integrity.sh`](scripts/verify_model_integrity.sh)
before it is loaded.

The mapping of each control to GDPR, ISO/IEC 27001:2022 Annex A and
SOC 2 trust services criteria is in
[`docs/COMPLIANCE.md`](docs/COMPLIANCE.md). The full threat model and
disclosure policy is in [`docs/SECURITY.md`](docs/SECURITY.md).

---

## The bundled `llama.cpp` fork

SAP-Pentest does not run against an unmodified `llama.cpp`. The tree
under [`llama.cpp/`](llama.cpp/) carries nine local patches without
which the tool-calling loop deadlocks, the embedded WebUI cannot
reach the SAP MCP servers, and the CORS proxy returns 500 for every
non-port-80/443 target. The complete inventory, the rationale for
each patch, the rebuild steps for the WebUI bundle and a checklist
to verify a clean install live in
**[LLAMACPP_FORK.md](LLAMACPP_FORK.md)**.

In short: clone the repository, build `llama.cpp/` from the patched
sources, and run the stack from `start_llm.sh` and `start_all.sh`.
Do not replace `llama.cpp/` with a fresh upstream checkout.

---

## Repository layout

```
.
├── cli.py                      # operator CLI (engage / run / status / report)
├── start_all.sh                # bring up LLM + MCP servers + dashboard
├── stop_all.sh                 # graceful teardown
├── status_all.sh               # one-shot status check
├── monitor_all.sh              # multi-pane log monitor (konsole/tmux)
├── PENTEST_AGENT_MCP_SPEC.md   # full technical spec (Italian, ~1900 lines)
├── README.md                   # this file
├── parrot_tools.yaml           # generated catalog (145 tools)
│
├── core/                       # cross-cutting libraries
│   ├── models.py               # Pydantic models (Engagement, EngagementPhase, Finding, ...)
│   ├── executor.py             # ToolExecutor (audit + scope + sandbox)
│   ├── scope_validator.py      # infra + identity scope enforcement
│   ├── target_validator.py     # CIDR/domain/URL/identity normalization
│   ├── session_store.py        # aiosqlite persistence (encrypted at rest)
│   ├── audit_log.py            # JSONL audit
│   ├── parrot_catalog.py       # catalog loader + arg validators
│   └── ...
│
├── mcp_servers/                # 6 MCP servers
│   ├── engagement_server.py
│   ├── recon_server.py
│   ├── exploit_server.py
│   ├── blueteam_server.py
│   ├── parrot_server.py
│   └── osint_server.py         # identity / person OSINT (PII-aware)
│
├── agent/                      # LLM orchestrator + prompts
│   ├── orchestrator.py
│   ├── run_modes.py            # planning | execution | step
│   └── prompts/
│
├── sap_dashboard/              # FastAPI + frontend
├── scripts/                    # build_catalog, install, qa_scenario, ...
├── playbooks/                  # YAML playbooks (ad/web/network/mixed)
├── docs/                       # extra docs
│   └── osint.md                # identity OSINT tools reference
└── tests/                      # 413 tests (402 default + 11 live/lab)
```

---

## Documentation

**Repository root:**
- [PENTEST_AGENT_MCP_SPEC.md](PENTEST_AGENT_MCP_SPEC.md) — full engineering spec (Italian; canonical until translation completes).
- [PENTEST_AGENT_MCP_SPEC.en.md](PENTEST_AGENT_MCP_SPEC.en.md) — English executive summary + index into the Italian source.
- [LLAMACPP_FORK.md](LLAMACPP_FORK.md) — inventory of the nine `llama.cpp` patches and how to rebuild the fork.
- [AUTHORIZATION.md](AUTHORIZATION.md) — authorization requirements & RoE checklist (read before any engagement).
- [SECURITY.md](SECURITY.md) — vulnerability reporting (root entry point).
- [CONTRIBUTING.md](CONTRIBUTING.md) — development workflow, quality gate, release process.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) — Contributor Covenant 2.1.
- [CHANGELOG.md](CHANGELOG.md) — Keep-a-Changelog history.
- [LICENSE](LICENSE) — Apache-2.0 + ethical-use addendum.

**`docs/`:**
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — C4 + data-flow diagrams, persistence layout, configuration surface.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — production deployment (host bootstrap, systemd, TLS, external audit sink, upgrade).
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — operator runbook: common failures and recovery.
- [docs/SECURITY.md](docs/SECURITY.md) — full security policy & threat model.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) — GDPR / ISO 27001 / SOC 2 control mapping.
- [docs/IR_RUNBOOK.md](docs/IR_RUNBOOK.md) — incident response runbook.
- [docs/INSTALL.md](docs/INSTALL.md) — single-machine developer bootstrap.
- [docs/osint.md](docs/osint.md) — identity OSINT tools reference (PII handling rules included).

**Component-level:**
- [sap_dashboard/README.md](sap_dashboard/README.md) — dashboard quick start + API.
- [agent/prompts/system_prompt.md](agent/prompts/system_prompt.md) — agent behavior contract.
- [agent/prompts/mode_planning.md](agent/prompts/mode_planning.md),
  [agent/prompts/mode_execution.md](agent/prompts/mode_execution.md),
  [agent/prompts/mode_step.md](agent/prompts/mode_step.md) — per-mode instructions.

---

## License & disclaimer

SAP-Pentest is released by [Sigmanex](https://www.sigmanex.net) under
the Apache License 2.0 (see [LICENSE](LICENSE)) with an additional
ethical-use clause: use only on systems and identities for which you
hold explicit written authorization. The authors disclaim all
liability for misuse. The platform intentionally refuses to operate
outside its declared scope; do not attempt to bypass these controls.

The project exists primarily to make Sigmanex's security and
compliance practices auditable in the open. Bug reports, security
advisories and pull requests are welcome through the normal GitHub
channels described in [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).
