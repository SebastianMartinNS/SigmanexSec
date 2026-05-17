# Security Policy — SAP-Pentest (Sigmanex)

SAP-Pentest is published by [Sigmanex](https://www.sigmanex.net) as an
open-source demonstration of our internal security and compliance
practices. The same control fabric described here — authentication
hardening, scope enforcement, tamper-evident audit, GDPR-aware data
handling, container and process hardening — is what we ship in our
commercial deliverables.

## Supported versions

The `main` branch is the only supported version. Security fixes are
backported only to release tags created in the last 90 days.

## Reporting a vulnerability

* Email: **security@sigmanex.net** (PGP key fingerprint published in the
  repository root as `SECURITY.asc`).
* Acknowledgement within 48 h, triage within 5 business days.
* Coordinated disclosure window: 90 days from acknowledgement.
* Do **not** open a public issue for an unpatched vulnerability.

## Threat model (summary)

| Asset                          | Threat                                  | Control                                                |
|--------------------------------|-----------------------------------------|--------------------------------------------------------|
| Operator credentials           | Phishing, brute-force                   | Constant-time compare, rate limiter, lockout, CSRF, HttpOnly |
| Session tokens                 | Theft via XSS / sniffing                | itsdangerous-signed, Secure+HttpOnly, TLS, CSP+TT     |
| Engagement data                | Tamper, exfiltration                    | RBAC, BLAKE2b audit chain, append-only sink           |
| Sudo broker                    | Privilege escalation                    | UNIX socket only, peer-uid check, audit, no NNP-relax |
| MCP servers                    | Sandbox escape                          | systemd hardening, seccomp, RestrictAddressFamilies   |
| LLM context (n_ctx)            | Prompt-explosion DoS via tool stdout    | 4-layer cap: executor max_output_bytes, MCP hard cap (`SAP_MCP_HARD_CAP_BYTES`), agent-side smart truncation, pre-flight `SAP_PROMPT_TOKEN_BUDGET` guard |
| Logs                           | Repudiation                             | Hash chain + external sink + WORM mirror              |

## Dependencies

* Python deps pinned by hash in `requirements.lock`.
* Vendored frontend (Alpine, htmx, Tailwind) verified by SRI in
  `index.html`; refresh via `scripts/regen_vendor_sri.sh`.
* Container base: `docker.io/python:3.13-slim`, rebuilt weekly.

## Supply chain

* CI runs `pip-audit`, `bandit`, `semgrep`, and `trivy fs .` on every PR.
* All commits require signed-off-by + GPG signature (verified in CI).
* Releases are signed (`cosign`) and SLSA-3 provenance is published.

## Cryptographic primitives

* Operator credential check: constant-time comparison
  (`secrets.compare_digest`) against the values held in process memory
  by `sap_dashboard/backend/rbac.py`. Credentials are supplied through
  environment variables (`SAP_DASHBOARD_USER` / `SAP_DASHBOARD_PASS`,
  or the `SAP_DASHBOARD_USERS` JSON directory). The platform does
  not hash or persist them; protecting `.env` (mode `0600`, owned by
  the runtime user) is therefore part of the operator's deployment
  responsibility. A future release will add Argon2id at-rest hashing.
* Session token: HMAC-SHA256 via `itsdangerous.TimestampSigner`,
  signed with `SAP_SESSION_SECRET` (≥ 32 bytes, generated via
  `secrets.token_urlsafe(48)`). Idle TTL 1800 s, absolute TTL 28 800 s.
* CSRF token: 32-byte URL-safe random, double-submit cookie validated
  in constant time on every state-changing request.
* Audit chain: BLAKE2b-256 over the canonical JSON of each event,
  linked to the previous digest stored in `logs/audit.jsonl.head`.
* TLS: 1.2+ ciphers per Mozilla "intermediate" profile; HSTS preload
  emitted automatically when the dashboard is served behind a TLS
  proxy.

## Out of scope

Self-hosted deployments where the operator weakens the systemd unit,
disables `SAP_MLOCK_ALL`, exposes the dashboard beyond `127.0.0.1`, or
runs the container as root.
