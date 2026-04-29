## Summary

<!-- One paragraph: what changes and why. Link the relevant section of
PENTEST_AGENT_MCP_SPEC.md if you touch architecture. -->

## Type of change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation only
- [ ] Hardening / security control
- [ ] CI / build / chore

## Authorization & scope impact

- [ ] No change to `core/scope_validator.py`, `core/target_validator.py`, or any MCP scope check
- [ ] Scope/auth code changed — tests added that prove **deny by default**
- [ ] No new way to invoke a tool that bypasses `ToolExecutor.run`

## PII / GDPR impact

- [ ] No PII is processed by this change
- [ ] PII is processed; the path sets `pii=True` and `identity_target=` correctly
- [ ] `docs/osint.md` and/or `docs/COMPLIANCE.md` updated accordingly

## Quality gate (run locally)

- [ ] `ruff check .`
- [ ] `bandit -ll -ii -r core sap_dashboard agent mcp_servers --exclude llama.cpp,build,sap_dashboard/frontend`
- [ ] `pip-audit -r requirements.txt --strict`
- [ ] `pytest -q` — all 402 default tests pass
- [ ] (if applicable) `SAP_LIVE_OSINT=1 pytest -m live` — passes or skips cleanly
- [ ] (if applicable) `python scripts/qa_scenario.py`

## Documentation

- [ ] `README.md` updated if user-visible behavior changed
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] `PENTEST_AGENT_MCP_SPEC.md` updated for architectural changes
- [ ] `docs/COMPLIANCE.md` updated if a control listed there changed

## Commits

- [ ] Commits are signed off (`-s`) and GPG-signed (`-S`)
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, ...)

## Linked issues

Closes #
