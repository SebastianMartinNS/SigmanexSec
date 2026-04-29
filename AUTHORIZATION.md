# Authorization Requirements

SAP-Pentest is a [Sigmanex](https://www.sigmanex.net) open-source
release. Publishing it does **not** lower the authorization bar
required to use it: the platform performs *active* security testing
and the legal exposure of running it without proper authorization
rests entirely on the operator.

> **Read this before creating any engagement.** Operating SAP-Pentest
> against systems or identities you do not own, without explicit written
> authorization from the legitimate owner, is illegal in virtually every
> jurisdiction and is a violation of this project's license addendum.

## 1. What "authorization" means here

SAP-Pentest enforces **two independent authorization artefacts** per
engagement:

| Field                       | Required for                                   | Example                |
|-----------------------------|------------------------------------------------|------------------------|
| `authorization_ref`         | Infrastructure scope (CIDR, domain, URL)       | `ROE-2026-0001`        |
| `osint_authorization_ref`   | Identity scope (email, username, person, handle) | `ROE-OSINT-2026-0001`|

Both are **non-empty strings** that must point to a document you can
produce on demand to an auditor or a court. The platform refuses to act
on identity targets if `osint_authorization_ref` is empty, even if
infra authorization is present.

## 2. Minimum content of the Rules of Engagement (RoE)

A defensible RoE document must contain at least:

1. **Parties**: legal entity owning the asset(s), legal entity
   performing the test, named operators.
2. **Scope (infra)**: explicit CIDRs / domains / URLs. Wildcards are
   discouraged; if used, list the resolved set.
3. **Scope (identity, if applicable)**: explicit emails, usernames,
   persons, social handles. SAP enforces hard-match, case-insensitive,
   normalized — see [`docs/osint.md`](docs/osint.md).
4. **Out of scope**: assets / techniques explicitly forbidden
   (e.g. denial of service, social engineering, third-party SaaS).
5. **Time window**: start / end timestamps in a named timezone.
6. **Allowed techniques**: PTES phase coverage you authorize
   (recon, exploitation, lateral movement, etc.).
7. **Prohibited techniques**: anything that could affect availability,
   integrity of production data, or third parties.
8. **Communication & escalation**: 24×7 contact for the asset owner,
   stop-test trigger, breach-notification handoff.
9. **Data handling**: storage location, retention, GDPR roles
   (controller / processor), right-to-erasure procedure
   (see `scripts/gdpr_erase.py`).
10. **Signatures**: handwritten or qualified electronic signatures of
    both parties, dated.

Store the signed PDF outside the repository. Reference its identifier
(filename, hash, ticket id, contract number) in the engagement.

## 3. What SAP enforces automatically

* `core/scope_validator.py` — every infra target is matched against the
  declared CIDRs / domains / URLs. Out-of-scope → `ScopeError`, no
  execution, audit entry written.
* `core/scope_validator.py` (identity branch) — every PII target is
  matched against the declared identity scope with normalization
  (lower-case email local-part, IDNA for domains, NFKC for usernames).
  No DNS fallback, no wildcard, no soft-allow.
* `core/target_validator.py` — input shape validation (CIDR / FQDN /
  URL / email / username) before any scope check.
* `core.executor.ToolExecutor` — single choke point for tool execution.
  Writes `logs/audit.jsonl` with BLAKE2b hash chain, optionally mirrored
  to syslog and a WORM volume.
* MCP servers — refuse `parrot_tool_run` / OSINT calls when the
  matching authorization reference is missing.

## 4. What SAP does **not** verify

* Whether the RoE document you reference actually exists.
* Whether the operator named in the RoE is the operator running the
  command. (Use OS-level identity controls and the dashboard RBAC
  for that — see `sap_dashboard/backend/rbac.py`.)
* Whether the asset owner had the legal authority to authorize the test
  (e.g. cloud assets shared with another tenant).
* Local laws and contractual obligations specific to your jurisdiction.

These are operator responsibilities. The platform is a control layer,
not a legal opinion.

## 5. Practical checklist before `python cli.py engage`

- [ ] Signed RoE (or equivalent) on file, with a stable identifier.
- [ ] Asset owner reachable for the duration of the test.
- [ ] Backups / snapshots taken if the scope includes production.
- [ ] Time window communicated to the asset owner's SOC / monitoring.
- [ ] Out-of-band channel agreed for stop-test signal.
- [ ] If identity OSINT: separate, explicit `osint_authorization_ref`
      and an enumerated identity list (no wildcards).
- [ ] GDPR lawful basis identified (typically Art. 6 §1(b) contract or
      §1(f) legitimate interest with documented LIA).

## 6. Stopping a test

Operators can immediately halt a run with:

```bash
bash stop_all.sh        # graceful teardown of all services
# or, surgically:
sudo systemctl stop sap-dashboard sap-mcp@'*' sap-llm sap-sudo-broker
```

Audit chain integrity survives stop/start. See
[`docs/IR_RUNBOOK.md`](docs/IR_RUNBOOK.md) for the full IR procedure.

---

*By using SAP-Pentest you confirm that you have read and understood this
document, and that you accept full responsibility for any test you
launch with it.*
