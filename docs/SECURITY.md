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
| Operator credentials           | Phishing, brute-force                   | Argon2id hash, rate limiter, lockout, CSRF, HttpOnly   |
| Session tokens                 | Theft via XSS / sniffing                | itsdangerous-signed, Secure+HttpOnly, TLS, CSP+TT     |
| Engagement data                | Tamper, exfiltration                    | RBAC, BLAKE2b audit chain, append-only sink           |
| Sudo broker                    | Privilege escalation                    | UNIX socket only, peer-uid check, audit, no NNP-relax |
| MCP servers                    | Sandbox escape                          | systemd hardening, seccomp, RestrictAddressFamilies   |
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

* Password hashing: Argon2id (m=64MiB, t=3, p=4).
* Session token: HMAC-SHA256 via itsdangerous, 32-byte secret rotated on
  rotation event.
* Audit chain: BLAKE2b-256.
* TLS: 1.2+ ciphers per Mozilla "intermediate" profile; HSTS preload.

## Out of scope

Self-hosted deployments where the operator weakens the systemd unit,
disables `SAP_MLOCK_ALL`, exposes the dashboard beyond `127.0.0.1`, or
runs the container as root.
