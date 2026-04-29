# Security Policy

SAP-Pentest is published by [Sigmanex](https://www.sigmanex.net) as an
open-source demonstration of our security and compliance practices.
We take vulnerability reports against this codebase seriously and
treat them on the same priority track as our commercial deliverables.

The full security policy lives in [`docs/SECURITY.md`](docs/SECURITY.md).
This file is kept at the repository root because GitHub looks for
`SECURITY.md` here when rendering the **Security** tab.

## Quick reference

* **Report privately**: email `security@sigmanex.net` (PGP key fingerprint
  in `SECURITY.asc` if/when published). Do **NOT** open a public issue
  for an unpatched vulnerability.
* **Acknowledgement**: within 48 hours.
* **Triage**: within 5 business days.
* **Coordinated disclosure window**: 90 days from acknowledgement.
* **Supported branch**: `main` only. Fixes backported to release tags
  cut in the last 90 days.

## In scope

* Authentication / authorization bypass on the dashboard (port 8765).
* Sandbox / scope-validator escapes that allow tools to act outside the
  declared engagement scope.
* Sudo broker privilege escalation paths.
* Audit-chain tampering (BLAKE2b chain, WORM mirror).
* MCP server input validation (ports 9001–9006).
* Supply-chain (pinned dependencies, vendored frontend assets).

## Out of scope

* Self-hosted deployments where the operator weakens the systemd unit,
  disables `SAP_MLOCK_ALL`, exposes the dashboard beyond `127.0.0.1`,
  or runs the container as root.
* The bundled `llama.cpp/` tree — report upstream at
  https://github.com/ggerganov/llama.cpp/security.
* Findings that require already-compromised root on the host.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full threat model,
cryptographic primitives, and supply-chain controls.
