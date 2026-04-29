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

### Added
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
- Hardening tracks P0–P5: dashboard auth (Argon2id, sliding session,
  CSRF), rate limiter, RBAC, audit hash chain (BLAKE2b), audit external
  sink, CSP nonce, vendored assets with SRI, podman / systemd
  hardening, process hardening (mlockall, MDWE).

## [1.0.0] — 2026-04-24

### Added
- Initial specification: MCP servers for `recon`, `exploit`,
  `postexploit`; `ToolExecutor` with sandboxing; encrypted Session
  Store (aiosqlite); system prompt; PTES-aligned workflow.
