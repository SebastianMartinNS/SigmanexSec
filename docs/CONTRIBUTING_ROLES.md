# Contributing a new agent role

SAP-Pentest v3.0 ships six roles out of the box (Planner, Recon Analyst,
Exploit Developer, Post-Exploitation Operator, Blue Team Observer,
Reporter). The role catalog is **YAML-editable** so the community can
contribute new specialisms (WebAppPentester, IoTHardwareAuditor,
APIFuzzAnalyst, ...) without patching Python.

This guide walks through adding a new role end-to-end using a concrete
example: a **Web Application Pentester** specialised on OWASP Top 10
issues that the generic Recon Analyst is not optimised for.

## 1) Pick an identifier

Role ids are lowercase snake_case alnum (`web_app_pentester`,
`iot_hardware_auditor`, ...). Once published, an id **must never
change** — it is the key on the audit `role` field and on
`can_handoff_to` edges of other roles.

```bash
ROLE_ID=web_app_pentester
```

## 2) Write the YAML

Create `agent/roles/${ROLE_ID}.yaml`:

```yaml
id: web_app_pentester
name: Web Application Pentester
persona_prompt_path: agent/prompts/roles/web_app_pentester.md
allowed_tools:
  - sqlmap_scan
  - nuclei_scan
  - nikto_scan
  - whatweb
  - ffuf_fuzz
  - feroxbuster_scan
  - wafw00f_check
  - search_archival_memory
  - read_core_memory
  - record_finding
denied_tools:
  - "*shell*"
  - "*exfil*"
  - "*persistence*"
allowed_phases:
  - scanning
  - exploitation
can_handoff_to:
  - to: exploit_dev
    when: when a complex exploit chain needs deeper post-exploitation expertise
  - to: blueteam_observer
    when: when the chain needs detection coverage analysis
  - to: reporter
    when: when the web findings are ready for the report
capability_guards:
  requires_human_approval: false
  max_tool_calls_per_step: 6
```

The loader validates this at startup against
`agent.roles.schema.Role`. Reach for `pytest tests/test_v3_role_validator.py`
to surface validation errors early.

## 3) Write the persona prompt

Create `agent/prompts/roles/${ROLE_ID}.md`. The prompt is the *system
message* the role's LLM iteration receives, so write it for the LLM
audience, not for human contributors:

```markdown
# Role: Web Application Pentester

You are a **Web Application Pentester** specialised on OWASP Top 10 issues.
Your job is to take a web target identified by the Recon Analyst and
demonstrate impact on injection, authentication, access control,
SSRF, IDOR, and deserialization weaknesses.

## Your responsibilities
- Confirm classes of vulnerability with **minimal request volume**.
- Record findings with the exact request/response evidence.
- Map exploit chain when one weakness enables another (e.g. SQLi → file
  read → SSRF).

## What you must NOT do
- No exploitation outside the engagement scope.
- No destructive payloads (`--dump`, `--os-shell`, persistence) without
  explicit per-call human approval.

## Handoff protocol
Hand off to `exploit_dev` for deep post-exploitation, `blueteam_observer`
for detection coverage, or `reporter` when findings are ready.
```

Keep it concise — 30-60 lines is the sweet spot. The full prompt budget
guard in `agent/budget/token_budget.py` is sized for personas of this
length.

## 4) Run the validator

```bash
pytest tests/test_v3_role_validator.py -v
```

The registry test (`test_every_persona_prompt_exists_on_disk`,
`test_every_handoff_target_is_known`) automatically picks up your
new YAML and persona file. Errors are clear: missing handoff
target, missing persona file, duplicate id, invalid phase name.

## 5) Wire the role into a multi-agent run

```bash
export SAP_AGENT_MODE=multi
python cli.py run --engagement-id eng-xyz \
                  --initial-role web_app_pentester \
                  --objective "find OWASP Top 10 issues on https://target.example/"
```

The Coordinator routes the engagement to your role and applies your
`allowed_tools` / `allowed_phases` / `can_handoff_to` policy through the
`RoleValidator` chokepoint.

## 6) Submit the PR

When opening a pull request, please include:

- The YAML + persona Markdown files.
- A short paragraph in the PR description explaining the role's **why** —
  what gap does it close that the existing 6 roles do not cover.
- A new test in `tests/test_v3_role_validator.py` that asserts a typical
  in-scope tool call passes and a typical out-of-scope call is rejected
  by the validator.

We review for:

1. **Scope discipline** — `denied_tools` includes every globally
   destructive primitive (`*shell*`, `*exfil*`, `*persistence*`).
2. **Persona clarity** — the LLM-side prompt does not hide behaviour from
   the audit chain (no "internal" reasoning instructions).
3. **Handoff hygiene** — every outgoing edge has a `when` hint that the
   Coordinator can surface to the destination role.

PRs that satisfy these usually merge within a week.

## 7) When NOT to add a new role

The v3.0 catalog covers the canonical PTES specialists. Before proposing
a new role, ask:

- *Could the existing Recon Analyst handle this with a denylist tweak?*
  If yes, prefer that.
- *Could an existing role grow a new `allowed_tools` entry?* If yes,
  open a PR against the YAML.
- *Is the new role really a specialism, or is it a workflow change?*
  Workflow changes belong in the orchestrator, not in a new role.

We want the catalog to stay small enough that an operator can hold the
whole team in their head.
