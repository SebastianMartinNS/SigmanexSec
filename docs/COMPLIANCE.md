# Compliance mapping — SAP

This document maps SAP technical controls to the controls of the standards
we care about. It is **not** a certificate; it is the engineering
reference auditors and SecOps share when scoping audits.

## GDPR (Regulation (EU) 2016/679)

| Article                         | Requirement                                 | SAP control                                                              | Code reference                                          |
|---------------------------------|---------------------------------------------|--------------------------------------------------------------------------|---------------------------------------------------------|
| Art. 5 §1(a) lawfulness         | Process only in scope of a written mandate  | Engagement requires authorization artefact before scan                    | `core/scope_validator.py`                               |
| Art. 5 §1(c) data minimisation  | Strip or pseudonymise non-essential PII     | GDPR sanitiser on report export                                           | `core/gdpr.py`                                          |
| Art. 5 §1(d) accuracy           | Cryptographic integrity of audit            | BLAKE2b hash chain + WORM mirror                                          | `core/audit_log.py`, `core/audit_sink.py`               |
| Art. 5 §1(e) storage limitation | Retention with documented purpose           | Storage GC sweeps `runs/`, `sessions/`, `reports/` per retention table    | `core/storage_gc.py`                                    |
| Art. 5 §1(f) integrity / conf.  | At-rest encryption, hardened transport      | TLS 1.2+, mlockall, `MemoryDenyWriteExecute`, secret in `/etc/sap` 0750  | `sap_dashboard/backend/app.py`, `core/process_hardening.py` |
| Art. 17 right to erasure        | Subject-erasure tooling                     | `scripts/gdpr_erase.py` purges by subject id and rewrites audit-redacted | `core/gdpr.py`                                          |
| Art. 30 records of processing   | Tamper-evident processing log               | Audit chain + external sink                                               | `core/audit_log.py`                                     |
| Art. 32 security of processing  | Defense in depth                            | Authentication hardening, LLM output sanitisation, audit chain, CSP and vendored assets, container/process hardening, external sink (see PENTEST_AGENT_MCP_SPEC.md) | (see PENTEST_AGENT_MCP_SPEC.md)                         |
| Art. 33 breach notification     | < 72 h notification                         | IR runbook, contact tree                                                  | `docs/IR_RUNBOOK.md`                                    |

## ISO/IEC 27001:2022 — Annex A

| Control                                  | SAP control                                                | Reference                                              |
|------------------------------------------|------------------------------------------------------------|--------------------------------------------------------|
| A.5.15 access control                    | RBAC (operator/auditor/admin) + UI gating                  | `sap_dashboard/backend/rbac.py`                        |
| A.5.16 identity management               | Single operator identity, hashed credential, lockout       | `sap_dashboard/backend/auth.py`                        |
| A.5.17 authentication information        | Argon2id, sliding session, CSRF                            | `sap_dashboard/backend/auth.py`                        |
| A.8.2 privileged access rights           | Sudo broker over UNIX socket, peer-uid check               | `core/sudo_broker.py`                                  |
| A.8.5 secure authentication              | HttpOnly+Secure+SameSite=Strict cookie                     | `sap_dashboard/backend/app.py`                         |
| A.8.7 protection against malware         | Read-only rootfs, MDWE, `cap_drop=ALL`                     | `deploy/podman/*.container`, `deploy/systemd/*`        |
| A.8.12 data leakage prevention           | GDPR sanitiser, scope validator, allow-listed targets      | `core/gdpr.py`, `core/scope_validator.py`              |
| A.8.15 logging                           | BLAKE2b chain + external sink                              | `core/audit_log.py`, `core/audit_sink.py`              |
| A.8.16 monitoring activities             | CSP report-only, syslog sink                               | `sap_dashboard/backend/app.py`                         |
| A.8.23 web filtering                     | CSP nonce, no inline scripts                               | `sap_dashboard/frontend/index.html`                    |
| A.8.24 use of cryptography               | TLS 1.2+, BLAKE2b, Argon2id                                | `docs/SECURITY.md`                                     |
| A.8.28 secure coding                     | Pinned deps, hash-locked, signed commits                   | `requirements.lock`, CI                                |

## SOC 2 — Trust Services Criteria

| Criterion                              | SAP control                                                       |
|----------------------------------------|-------------------------------------------------------------------|
| CC6.1 logical access                   | RBAC, MFA-ready (TOTP hook in auth.py), session expiry           |
| CC6.6 transmission                     | TLS-only, HSTS, no mixed content (vendored assets)               |
| CC6.7 disposal                         | `gdpr_erase.py`, retention-based GC                              |
| CC7.2 monitoring                       | Audit chain + sink + IR runbook detection signals                |
| CC7.3 incident                         | IR runbook (`docs/IR_RUNBOOK.md`)                                |
| CC7.4 recovery                         | Container is reproducible from `Containerfile.dashboard`         |
| CC8.1 change management                | All changes via PR + tests + signed commits                      |

## Maintenance

* Review quarterly. Each change to a control listed here MUST update
  this document in the same PR.
* External auditors should be given access to this file plus
  `docs/SECURITY.md`, `docs/IR_RUNBOOK.md`, and the audit chain export.
