# Changelog

All notable changes to SAP-Pentest are documented here.
SAP-Pentest is published by [Sigmanex](https://www.sigmanex.net) under
Apache-2.0 with an ethical-use addendum (see [LICENSE](LICENSE)).

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The authoritative engineering log is
[`PENTEST_AGENT_MCP_SPEC.md`](PENTEST_AGENT_MCP_SPEC.md) §Changelog.
This file mirrors that log in the standard format expected by GitHub.

## [Unreleased]

### Added — v3.1.0-rc2 (consolidation Week 5)

The final release candidate before the 90-day soak window opens.
Closes the typing ratchet across the security core and activates the
60 % global coverage gate. No new features.

- **Q1 step 2 — mypy --strict ratchet extended.** Six secondary
  modules join the four primary chokepoints in the `typecheck-chokepoints`
  CI gate (no `continue-on-error`): `core/approval_gate.py`,
  `core/sudo_vault.py`, `core/sudo_broker.py`, `core/tool_output_store.py`,
  `core/parrot_catalog.py`, `core/logging.py`. The strict CI gate now
  covers ten modules in total. The transitive informational `typecheck`
  job continues to ratchet the rest of `core/`, `agent/`,
  `mcp_servers/` and `sap_dashboard/backend/`.
- **Q2 — coverage gate activated.** `pytest --cov-fail-under=60` is
  now blocking in CI. Baseline measured at 68 % on the v3 + legacy
  suite combined; the gate keeps a 8-point headroom for future test
  surface growth. Per-package gates (75 % `core/`, 50 % `agent/`)
  follow in v3.2 after the mypy ratchet finishes the remaining
  transitive modules.
- **S1 — soak smoke harness.** New `scripts/soak_smoke.py` drives the
  AgenticLoop with a deterministic scripted provider, records every
  iteration on the BLAKE2b chain via `AgentStepRecorder`, takes
  tracemalloc snapshots and writes a Markdown report to
  `reports/soak_<run_id>.md`. The in-process smoke variant runs in
  CI in seconds; operators wire the same script into a > 4 h soak
  with `LLM_PROVIDER=anthropic` (or any other configured provider)
  during the 90-day soak window.
- **S4 — replay acceptance.** `tests/test_v3_w4_observability.py`
  invokes `scripts/replay_run.py` as a subprocess over a recorded
  audit chain and asserts the structured summary plus the .jsonl and
  .md report files. Exit code 3 on unknown `run_id` is pinned by the
  test.

### Added — v3.0 cycle (Cognitive Architecture)

The v3.0 release reshapes SAP-Pentest from a single monolithic loop into
a multi-agent platform with compliance-grade observability. Everything
ships behind feature flags so deployments that worked in v2.3 keep
working unchanged.

- **Milestone A — Tracking compliance-grade** (gated by
  `SAP_V3_TRACKING_V2`, default `0`). Eight new action types enter the
  existing BLAKE2b hash chain: `llm_prompt_sent`,
  `llm_response_received`, `llm_reasoning`, `agent_step`, `role_handoff`,
  `phase_transition`, `reflection_completed`, `state_transition`. The
  schema is versioned (`details["v"] = 1`). New
  `core/audit_events.py` enumerates the catalog; new
  `core/tracking/events.py` provides typed factories. The recorder
  (`agent/tracking/recorder.py`) hooks into the orchestrator behind a
  null-recorder fallback so v2.3 callers see zero behaviour change.
  Sensitive payloads (raw prompt, raw response, reasoning, reflection)
  are Fernet-wrapped at rest via
  `core/tracking/encrypted_sink.py` — the key is derived from the
  existing `CREDENTIAL_ENCRYPTION_PASSPHRASE` so no new operator config
  is required. Prometheus counters / histograms / gauges in
  `core/observability/metrics.py`, exposed on `/metrics`. OpenTelemetry
  traces in `core/observability/tracing.py`, no-op unless
  `SAP_OTEL_ENDPOINT` is set. Passive replay via `scripts/replay_run.py`
  produces a Markdown + JSONL report per `run_id`. 12 acceptance tests
  in `tests/test_v3_tracking.py`.
- **Milestone B — SOLID refactor**. The provider Strategy lives in
  `agent/providers/` (Protocol in `base.py`, neutral types in
  `types.py`, `anthropic_provider.py` + `openai_provider.py`, factory
  in `factory.py`). `agent/loop/agentic_loop.py` collapses the two
  legacy `_run_anthropic` / `_run_openai` loops into a single
  provider-neutral driver. A custom ~250 LOC dependency-injection
  container lives in `core/di/container.py` (no external dep). The
  fat 13-parameter `ToolExecutor.run` keeps its signature for backward
  compatibility but gains a typed companion `ToolExecutor.run_request`
  that takes a `core/executor_types.ToolCallRequest`. MCP servers
  share a common bootstrap via `mcp_servers/base.py`. Budget guard
  and fuzzy circuit-breaker move to standalone `agent/budget/*.py`
  modules. 27 acceptance tests across
  `test_v3_provider_parity.py`, `test_v3_di_container.py`, and
  `test_v3_budget_breaker.py`.
- **Milestone C — Multi-agent team** (gated by `SAP_AGENT_MODE`,
  default `single`). Six role personas ship in `agent/roles/*.yaml`
  with matching Markdown prompts in `agent/prompts/roles/`: Planner,
  Reconnaissance Analyst, Exploit Developer, Post-Exploitation
  Operator, Blue Team Observer, Reporter. The role catalog is
  community-editable — see `docs/CONTRIBUTING_ROLES.md` for the
  contribution flow. A new chokepoint `core/role_validator.py`
  composes on top of `scope_validator` to enforce per-role tool /
  phase / handoff policy via Pydantic-validated YAML at startup.
  The explicit state machine in `agent/state/machine.py` codifies the
  ReAct cycle (`idle → planning → acting → observing → reflecting →
  handing_off → done|failed`). `agent/coordinator.py` schedules
  role-to-role work for one engagement via
  `agent/coordination/handoff.py:AgentContext`. 35 acceptance tests
  across `test_v3_role_validator.py`, `test_v3_state_machine.py`,
  `test_v3_multi_agent_e2e.py`. Migration walkthrough in
  `docs/migration_v2.3_to_v3.0.md`.
- **Milestone D — Distribution**. New parametrized OCI image at
  `deploy/podman/Containerfile.service` builds the orchestrator and
  all six MCP server images from a single Containerfile via
  `--build-arg SAP_SERVICE=...`. New
  `deploy/compose/docker-compose.yml` brings up the whole stack
  locally (orchestrator + 6 MCP + dashboard + Prometheus + optional
  OTel collector). Example `.env`, Prometheus scrape config and OTel
  collector config live alongside. Helm chart is deferred to v3.1 to
  keep the v3.0 maintenance surface tight.

### Identity hygiene (v3.0 P0 fix)

- Replaced personal email in `pyproject.toml` `authors` and
  `docs/THREAT_MODEL.md` maintainer block with the public alias
  `rootedlab-code <rootedlab@proton.me>`. Repo-local git identity
  switched to the same alias. The personal email
  (`adriansebastianmartin@gmail.com`) is no longer present in any
  tracked file.

### Added — v2.3 cycle (Security Hardening)
- **OS-level sandbox** for every tool execution. New `core/sandbox.py`
  wraps `core/executor.ToolExecutor.run()` in a `bwrap` invocation
  driven by per-category JSON profiles
  (`deploy/sandbox/profiles/{recon,exploit,osint,blueteam,parrot,engagement}.json`)
  conforming to `profile.schema.json`. Default in v2.3 is
  `SAP_SANDBOX=warn` — the sandbox is computed and audited via
  `sandbox.warn` events but NOT enforced, so operators validate
  profiles against real engagements before v2.4 flips the default to
  `on`. A new `.github/workflows/ci-sandbox.yml` runs the real escape
  suite on the dedicated self-hosted runner (label `self-hosted-userns`,
  requires `kernel.unprivileged_userns_clone=1`). v2.3 limitation:
  sudo-required tools run unwrapped because `sudo` strips setuid
  inside a user namespace; a privileged-sandbox proxy is on the v2.4
  roadmap. Tests: `tests/test_sandbox_module.py` (26),
  `tests/test_sandbox_warn_mode.py` (5), `tests/test_sandbox_bwrap.py`
  (5, gated by `@pytest.mark.sandbox`).
- **Argon2id at-rest credentials**. `argon2-cffi>=23.1.0` promoted to
  a core dependency (the "no plaintext in memory" gap is closed only
  if every install hashes). New `core/credentials.py` wraps the
  library with the OWASP 2024 baseline (`m=64 MiB, t=3, p=4`,
  `argon2id`). `sap_dashboard/backend/rbac.py` and `deps.py` now
  verify against `pass_hash` (Argon2id) entries in
  `SAP_DASHBOARD_USERS`; legacy plaintext `pass` entries still work
  for one release of grace but emit an `auth.cred.plaintext.deprecated`
  audit event on every successful login.
  `scripts/migrate_creds_v23.py` migrates `.env` plaintext entries in
  place (with optional backup and dry-run) so operators can roll
  forward without downtime. Tests: `tests/test_credentials_argon2.py`
  (16, covers hash/verify/needs_rehash + RBAC integration + bootstrap).
- **RBAC enforced on every dashboard route**. Three-tier matrix
  (`viewer` / `operator` / `admin`) declared via
  `Depends(require_role(...))` on the router constructor of each file
  in `sap_dashboard/backend/routes/`, with route-level overrides
  where a single router mixes roles (e.g. `runs.py` is viewer-base
  with POST/PATCH/approve bumped to operator). `tests/test_p2_rbac_enforcement.py`
  introspects `app.routes` and FAILS if any route lacks both a
  `require_role` dependency and an entry in the public allow-list —
  any new route forces an explicit RBAC decision in the PR review.
- **SSO connectors** for OIDC and SAML in `sap_dashboard/backend/sso/`.
  OIDC ships in the base image (`authlib>=1.3.0` is a core dep) with
  routes `/api/auth/sso/login` and `/api/auth/sso/callback`
  (Authorization Code + state cookie + signed nonce, IdP claims
  mapped to roles via `SAP_SSO_ROLE_MAP`, successful login emits
  `auth.login.sso` audit event). SAML is opt-in via the new
  `[sso-saml]` extra (`pip install 'sap-pentest[sso-saml]'`,
  requires `libxml2-dev libxmlsec1-dev libxmlsec1-openssl` on the
  host); endpoints return HTTP 501 with the install command when the
  extra is missing, so the operator never silently falls back.
  Local users (`SAP_DASHBOARD_USERS`) remain the always-available
  fallback. Tests: `tests/test_sso_oidc.py` (10, covers config
  parsing + redirect flow + SAML-501 contract). Full Dex E2E in CI
  is a v2.4 workstream.
- **Signed release pipeline** (`.github/workflows/release.yml`).
  Triggered by `v*.*.*` tags from the `SigmanexSec` org: builds
  sdist + wheel, generates an SBOM (SPDX + CycloneDX) with `syft`,
  signs every artefact with `cosign sign-blob` keyless via the
  Sigstore Fulcio OIDC issuer (no private key to store), emits
  SLSA-3 provenance via `slsa-framework/slsa-github-generator@v2.0.0`,
  and verifies its own signatures before publishing the GitHub
  release. Containers are explicitly out of scope for v2.3 — they
  land in Fase 4.1 (v3.0). Downstream verification is documented in
  the workflow header and threat model.
- **Formal threat model** at [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md):
  STRIDE per trust boundary across all seven boundaries (Operator ↔
  Dashboard → Orchestrator → LLM / MCP → ToolExecutor → sandboxed
  tool → target estate), with a controls-and-residuals table per
  boundary and an explicit list of known gaps (external-LLM opt-in
  granularity, multi-tenant isolation, sandbox-enforcement default,
  sudo-required tool sandboxing, custom-secret regex catalogue,
  operator-host integrity). Includes the CVD process and 90-day
  disclosure window.

### Fixed — v2.2 ratchet (Pre-Fase 2 technical-debt cleanup)
- **`ruff check .` is now zero**: the baseline of 656 violations introduced
  by Fase 1's new ruleset has been resolved. Distribution:
  - **513 auto-fixed** by `ruff check --fix` (unused imports, import order,
    minor refactors).
  - **47 `B904` chaining bugs** in `core/`, `mcp_servers/` and the
    dashboard routes — every `raise` inside an `except` now carries
    `from err` (or `from None` where the chain is intentionally
    suppressed) so tracebacks no longer lose causal context.
  - **18 `E70x` multi-statement-per-line** in `cli.py`, `core/parrot_catalog.py`,
    `core/tool_output_store.py`, `sap_dashboard/backend/routes/export.py`
    split into idiomatic Python.
  - **`mcp_servers/recon_server`** migrated from `xml.etree.ElementTree`
    to `defusedxml.ElementTree` for parsing **attacker-controlled** nmap
    `-oX` output. Added `defusedxml>=0.7.1` to core dependencies.
  - Remaining `S6xx` / `S1xx` warnings (SQL templates with hardcoded
    column-name fragments, test fixtures with throwaway secrets, etc.)
    annotated with `# noqa` carrying the justification inline.
- Categories that recur uniformly across the codebase as documented
  project patterns added to `[tool.ruff.lint.ignore]` with a comment
  explaining why: `E402` (post-`sys.path.insert` imports in entrypoint
  scripts), `S108` (`/tmp` + `$XDG_RUNTIME_DIR` fallback paths),
  `S110`/`S112` (defensive `try/except: pass|continue` for graceful
  degrade of optional integrations).
- Legacy root-level dev scripts (`test_tool_calling.py`,
  `test_mcp_tool_calling.py`) added to `extend-exclude`.
- `.github/workflows/ci.yml` lint job lost its `continue-on-error: true`
  — any new ruff violation now blocks PRs.
- `scripts/apply_llamacpp_patches.sh` accepts `--check` for non-mutating
  dry-run; the CI `llamacpp-patches` job invokes it whenever the
  submodule or `patches/` change.

### Added — v2.2 cycle (Foundation & Hygiene)
- **Proper Python packaging**. `pyproject.toml` now declares
  `[build-system]`, `[project]`, and `[project.scripts]`; the project
  ships as a real wheel (`sap-pentest`) with two console entry points
  (`sap-pentest`, `sap-mcp-runner`). A new `MANIFEST.in` includes
  `parrot_tools.yaml`, the four playbooks, agent prompts, frontend
  bundles and deployment material in the sdist.
- **Optional dependency groups**: `[ml]` (tiktoken + sentence-transformers,
  loaded lazily by `core/memory/{tokens,embeddings}.py` with graceful
  fallbacks — moving them out of the core dep set drops ~600 MB of
  torch wheels from the default install), `[argon2]` (preparing for
  v2.3 credential hashing), `[sso]` (OIDC + SAML), `[observability]`
  (Prometheus + OpenTelemetry), `[dev]` (pytest, ruff, mypy, bandit,
  pip-audit, build, pip-tools, type stubs), `[all]` aggregate.
- **Hash-locked dependency files**: `requirements.lock` and
  `requirements-dev.lock` generated by
  [`scripts/lock_deps.sh`](scripts/lock_deps.sh) using
  `pip-compile --generate-hashes --allow-unsafe --strip-extras`. The
  references already present in `docs/COMPLIANCE.md` (A.8.28 secure
  coding) and `docs/SECURITY.md` are now backed by actual files;
  `pip install --require-hashes -r requirements.lock` is the
  reproducible install path.
- **`mypy --strict` baseline** declared in `pyproject.toml` with
  per-module overrides for the modules still pending audit; each PR
  can ratchet one module to clean strict.
- **Full CI workflow** at [`.github/workflows/ci.yml`](.github/workflows/ci.yml):
  ruff (lint), mypy (`--strict`), bandit, semgrep
  (p/python + p/secrets + p/owasp-top-ten), trivy fs (vuln + secret +
  misconfig), pip-audit on `requirements.lock`, full pytest with
  `pytest-cov`, wheel build + smoke install, and a `llama.cpp` patch
  dry-run when the submodule or patches dir changes. The old
  `security.yml` was reduced to a weekly CVE re-scan.
- **Structured logging** via `structlog` in
  [`core/logging.py`](core/logging.py): JSON in containers / CI,
  coloured console on a TTY, correlation-id contextvar +
  `CorrelationIdMiddleware` (FastAPI) propagating `X-Correlation-Id`
  end-to-end. Wired into `cli.py` and `sap_dashboard/backend/app.py`
  as the first adopters; other modules will migrate incrementally
  during the v2.2 cycle. **Distinct** from `core/audit_log.py` — the
  audit chain stays canonical and tamper-evident.
- **Operational liveness / readiness probes** at
  [`sap_dashboard/backend/routes/health.py`](sap_dashboard/backend/routes/health.py)
  and inside [`mcp_http_runner.py`](mcp_http_runner.py):
  `GET /healthz` (cheap, always 200 while the process lives) and
  `GET /readyz` (200/503 with a per-check breakdown of sqlite + audit
  log directory + sudo-broker socket). Both bypass auth, CSRF and the
  rate limiter so a Kubernetes / systemd / load-balancer probe never
  pollutes audit or burns the anon bucket.
* `mcp_http_runner.py` was refactored so module import has no side
  effects (`main()` is the entry point) and exposes the new probes via
  an ASGI wrapper alongside the pre-existing 400 → 404 session-id
  patch. The `sap-mcp-runner` console script now binds to that
  function.
- **Log rotation** added to
  [`core/storage_gc.py`](core/storage_gc.py) as `_rotate_logs()`:
  size 100 MiB / age 14 days / keep 14 archives (all
  env-overridable), gzipped, in-place truncation so daemons that hold
  the file descriptor keep writing without losing records.
  `audit.jsonl` is intentionally excluded — it owns its own rotation
  in `core/audit_log.py` to preserve the BLAKE2b chain.
- **Property-based tests** for the scope chokepoint at
  [`tests/test_scope_validator_property.py`](tests/test_scope_validator_property.py):
  eleven Hypothesis properties × 500 random samples each =
  5 500 random inputs proving fail-closed semantics, suffix-only
  matching, hard-match identity scope (no wildcard), case-insensitive
  normalisation and the username ↔ social-handle cross-bucket
  symmetry. No bypass surfaced.
- **English-first documentation**: new
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (Mermaid C4 + data
  flow + persistence layout), [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
  (production setup, systemd units, TLS termination, audit sinks),
  [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) (operator
  runbook). The 79 KB
  [`PENTEST_AGENT_MCP_SPEC.md`](PENTEST_AGENT_MCP_SPEC.md) (Italian)
  is unchanged; a sibling English index lives at
  [`PENTEST_AGENT_MCP_SPEC.en.md`](PENTEST_AGENT_MCP_SPEC.en.md) and
  the full translation is tracked as a follow-up workstream.

### Added
- **Prompt-budget hardening sprint** (resolves the 346 K-token llama.cpp
  HTTP 400 regression observed on 2026-04-30). Defence in depth at four
  layers:
  - `core/memory/tokens.count_message_tokens` now walks Anthropic SDK
    content blocks (`TextBlock`, `ToolUseBlock`, `ToolResultBlock`) via
    duck-typing; previously they contributed 0 tokens to the budget so
    compaction never fired on the Anthropic provider path.
  - `mcp_servers/_response.build_tool_response` enforces an absolute
    hard cap (`SAP_MCP_HARD_CAP_BYTES`, default 32 KB) on every profile
    including `full`, surfacing `truncation_enforced: true`. The
    matching `read_tool_output_*` recall handler clamps every read mode
    to `SAP_MCP_RECALL_CAP_BYTES` (default 64 KB) and reports
    `recall_cap_bytes` so callers can paginate.
  - `mcp_servers/recon_server` and `mcp_servers/exploit_server.identify_hash`
    no longer ship `result.stdout` integrally on JSON-parse failure;
    they emit a bounded head+tail snippet via the new
    `_parse_error_snippet` helper, plus `output_ref` / `full_size_bytes`
    so the agent can recall the full output on demand.
  - New pre-flight token guard in `agent/orchestrator.Orchestrator.
    _prompt_budget_guard` runs before every `messages.create` /
    `chat.completions.create`. If `count_message_tokens` exceeds
    `SAP_PROMPT_TOKEN_BUDGET` (default 170 000 — comfortably below the
    200 704-token `n_ctx_slot`), it prunes the longest message content
    iteratively and aborts with a structured `error` event if the
    prompt cannot be reduced under budget. Always emits `token_budget`
    observability events when above `SAP_PROMPT_TOKEN_WARN`.
- New MCP meta-tool `set_run_context_<suffix>` on every server that owns
  a `ToolExecutor` (recon, exploit, parrot, osint). The orchestrator
  now broadcasts `set_run_context` at run start
  (`Orchestrator._broadcast_run_context`), re-enabling the
  spill-to-disk persistence layer that was silently OFF whenever the
  MCP servers were constructed with `run_id=""` (i.e. always, in the
  default deployment).
- New tests: `tests/test_prompt_budget.py` (11 cases covering Anthropic
  block counting, hard-cap enforcement on `full` and `head_tail`
  profiles, recon snippet bounds, and the pre-flight guard's three
  outcomes); two new cases in `tests/test_executor_persistence.py`
  pinning the `run_id=""` no-persist contract and the `set_run_id`
  re-bind behaviour.

### Changed
- `mcp_servers/recon_server` returns now always include `call_id`,
  `output_ref`, and `full_size_bytes` (previously omitted on the four
  raw-stdout fallback paths).
- New environment knobs:
  `SAP_PROMPT_TOKEN_BUDGET`, `SAP_PROMPT_TOKEN_WARN`,
  `SAP_MCP_HARD_CAP_BYTES`, `SAP_MCP_RECALL_CAP_BYTES`. All have safe
  defaults; nothing changes for existing deployments unless they were
  relying on the (broken) unbounded raw-stdout passthrough.

### Added (pre-sprint)
- Sigmanex branding across root documentation; new
  [LLAMACPP_FORK.md](LLAMACPP_FORK.md) inventorying the nine local
  patches against `ggerganov/llama.cpp` (tool-call promotion in
  `common/chat.cpp`, CORS proxy host:port handling, WebUI MCP
  defaults, JSON-mode HTTP transport, and more) with rebuild and
  verification steps.
- Repository-level `LICENSE` (Apache-2.0 + ethical-use addendum),
  `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`,
  `AUTHORIZATION.md`, `.gitignore`, and GitHub issue / PR templates.

### Changed
- README and ancillary docs no longer label hardening tracks as
  "P0–P5" or capabilities as "Phase 8". Each control is now
  described by what it actually does (authentication hardening,
  LLM output sanitisation, audit chain and GDPR, CSP and vendored
  assets, container and process hardening, external audit sink and
  incident response).

## [2.1.0] — Identity OSINT capability (formerly "Phase 8")

### Added
- New engagement fields: `scope_emails`, `scope_usernames`,
  `scope_persons`, `scope_social_handles`, `osint_authorization_ref`
  (separate from infra `authorization_ref`).
- New MCP server `mcp_servers/osint_server.py` on port **9006** with 9
  tools: `sherlock_run`, `maigret_run`, `holehe_run`, `h8mail_run`,
  `whatsmyname_run`, `social_analyzer_run`, `ghunt_email`,
  `recon_ng_batch`, `spiderfoot_batch`.
- `ScopeValidator.assert_identity_in_scope(value, kind, engagement_id)`
  with **hard-match** case-insensitive normalization (no DNS fallback,
  no wildcard).
- `ToolExecutor.run(..., identity_target=(value, kind), pii=True)`
  mutually exclusive with infra `target=`. Every PII execution is logged
  with `pii=true` in `logs/audit.jsonl` for GDPR right-to-erasure.
- Catalog category `osint` (9 descriptors with `pii=True`) and
  `pipx` installer block in `scripts/install_missing_tools.sh`.
- Test suite `tests/test_osint_*` (full flow, integration, identity
  scope, live with `SAP_LIVE_OSINT=1`).

## [2.0.0] — 2026-04-25

### Added
- **Section 17 — Control Dashboard SAP**: full FastAPI web UI for
  engagement and task management (port 8765).
- **Section 18 — Sudo Elevation Subsystem**: in-memory sudo credential
  vault and privileged-action workflow over a UNIX socket
  (`core/sudo_broker.py`, `core/sudo_vault.py`).
- **Section 19 — Full Parrot OS Tool Catalogue**: declarative catalog
  of all installed offensive tools (~145), exposed via the generic MCP
  tools `parrot_tool_run` / `parrot_list_tools` /
  `parrot_tool_describe` / `parrot_session_*`.
- **Section 20 — Agent Run Modes**: Planning Mode vs Execution Mode,
  plus Step Mode with human-in-the-loop approvals.
- Hardening tracks P0–P5: dashboard auth (constant-time credential
  check, sliding session, CSRF), rate limiter, RBAC, audit hash chain
  (BLAKE2b), audit external sink, CSP nonce, vendored assets with SRI,
  podman / systemd hardening, process hardening (mlockall, MDWE).

## [1.0.0] — 2026-04-24

### Added
- Initial specification: MCP servers for `recon`, `exploit`,
  `postexploit`; `ToolExecutor` with sandboxing; encrypted Session
  Store (aiosqlite); system prompt; PTES-aligned workflow.
