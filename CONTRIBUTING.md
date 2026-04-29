# Contributing to SAP-Pentest

SAP-Pentest is a [Sigmanex](https://www.sigmanex.net) open-source
release. We publish it because we think the practices baked into the
code — deny-by-default scope enforcement, single audited execution
choke point, GDPR-aware identity OSINT, hardened runtime — are worth
sharing and worth scrutinising. Contributions that strengthen those
guarantees are welcome; contributions that weaken them are not.

Every change is evaluated against the **authorization-first** and
**audit-everything** guarantees described in
[`PENTEST_AGENT_MCP_SPEC.md`](PENTEST_AGENT_MCP_SPEC.md).

## Code of Conduct

By participating you agree to abide by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Ground rules

1. **Never weaken scope enforcement.** `core/scope_validator.py`,
   `core/target_validator.py`, and the per-server scope checks are the
   foundation of the platform. Any change here requires tests proving
   that the failure mode is *deny by default*.
2. **Never bypass the audit log.** Every tool execution must go through
   `core.executor.ToolExecutor.run` (or the identity variant). Direct
   `subprocess.*` calls in MCP server code are not accepted.
3. **No new secrets in the repo.** Use `.env` (see `.env.example`) or
   `/etc/sap/secrets.env` in production. CI scans for credentials on
   every PR.
4. **PII is special.** OSINT/PII tools must set `pii=True` and pass
   `identity_target=(value, kind)` so the audit chain marks the entry
   for GDPR right-to-erasure (`scripts/gdpr_erase.py`).

## Development setup

```bash
git clone <repo> sap-pentest && cd sap-pentest
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest pytest-asyncio ruff bandit pip-audit
cp .env.example .env        # adjust to your local LLM
```

The `llama.cpp/` tree under the repository is a **patched fork**, not
upstream. Read [`LLAMACPP_FORK.md`](LLAMACPP_FORK.md) before touching
anything inside `llama.cpp/`: the WebUI bundle has to be rebuilt
after changes to `tools/server/webui/src/**`, and the nine local
patches must survive any upstream merge.

For the GPU/LLM stack see `start_llm.sh`, `install_gpu.sh` and the
notes in `/memories/repo/sap_llm_config.md`-style operator runbooks.

## Workflow

1. Create a topic branch off `main`: `feat/<short-name>` or
   `fix/<short-name>`.
2. Write the failing test first when fixing a bug.
3. Run the local quality gate **before** opening a PR:

   ```bash
   ruff check .
   bandit -ll -ii -r core sap_dashboard agent mcp_servers \
     --exclude llama.cpp,build,sap_dashboard/frontend
   pip-audit -r requirements.txt --strict
   pytest -q                                    # 402 tests, ~25s
   ```

4. Sign your commits (`git commit -s -S`). DCO sign-off + GPG signature
   are checked in CI (see `.github/workflows/security.yml`).
5. Open the PR using the template (`.github/pull_request_template.md`).
   Link the relevant section of `PENTEST_AGENT_MCP_SPEC.md` if you
   change architecture.

## Test tiers

| Tier            | Command                                                  | When it runs |
|-----------------|----------------------------------------------------------|--------------|
| default         | `pytest -q`                                              | every PR     |
| live OSINT      | `SAP_LIVE_OSINT=1 pytest tests/test_osint_live.py -m live` | on demand   |
| lab end-to-end  | `PENTEST_LAB_CIDR=10.10.10.0/24 pytest -m lab`           | on demand   |
| QA scenario     | `python scripts/qa_scenario.py`                          | on demand   |

`live` and `lab` markers are deselected by default in `pyproject.toml`.

## Adding a new tool to the catalog

1. Add the descriptor to `parrot_tools.yaml` (use
   `scripts/build_catalog.py` to regenerate from the live system).
2. Provide an arg validator in `core/parrot_catalog.py`.
3. Add at least one unit test under `tests/` exercising the validator
   and one integration test driving `parrot_tool_run`.
4. If the tool processes PII, set `pii: true` in the descriptor and add
   a scope check to the MCP server that exposes it.
5. Update `docs/osint.md` (PII tools) or the relevant spec section.

## Documentation

Documentation files live at the repository root (`README.md`,
`PENTEST_AGENT_MCP_SPEC.md`, `CONTRIBUTING.md`, ...) and under `docs/`
(`SECURITY.md`, `COMPLIANCE.md`, `IR_RUNBOOK.md`, `osint.md`). When you
change a control mentioned in `docs/COMPLIANCE.md`, update both files
in the same PR.

## Releasing

Releases are tagged `vMAJOR.MINOR.PATCH` and signed with `cosign`.
Update `CHANGELOG.md` (Keep-a-Changelog format) in the release PR.

## Questions

Open a Discussion (preferred) or a `question` issue. For sensitive
matters, use the security mailbox listed in `SECURITY.md`.
