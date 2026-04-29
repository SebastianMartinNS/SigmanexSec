"""End-to-end smoke test for the OSINT → reporting fast-track.

Covers Phase A1 + B1 + C3 fixes together:

  * `parrot_tool_run("sherlock_run", ...)` succeeds on a username target
    when ``scope_usernames`` and ``osint_authorization_ref`` are set,
    proving the OSINT routing fix.
  * Missing OSINT binaries surface ``setup_required`` instead of
    ``FileNotFoundError`` (B1 graceful degradation).
  * ``generate_assessment_report`` writes a file under ``REPORTS_DIR``.
  * The orchestrator's ``_maybe_autoreport`` hook fires on
    ``set_phase("reporting")``.

The executor is monkeypatched, so no real binary runs.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.models import Engagement, EngagementCreate
from core.session_store import SessionStore


def _patch_parrot_exe(monkeypatch, stdout: str = ""):
    """Stub `ToolExecutor.run` used by parrot_server, honoring scope."""
    from mcp_servers import parrot_server as srv
    from core.executor import ExecutionResult

    async def fake_run(self, *args, **kwargs):
        identity = kwargs.get("identity_target")
        if identity is not None and self._scope is not None:
            value, kind = identity
            self._scope.assert_identity_in_scope(
                value, kind, kwargs.get("engagement_id", "")
            )
        target = kwargs.get("target")
        if target is not None and self._scope is not None:
            self._scope.assert_in_scope(target, kwargs.get("engagement_id", ""))
        out = stdout or (
            "[+] GitHub: https://github.com/octocat\n"
            "[+] HackerNews: https://news.ycombinator.com/user?id=octocat\n"
        )
        return ExecutionResult(
            tool=kwargs.get("tool", "sherlock"),
            command="sherlock --print-found octocat",
            stdout=out,
            stderr="",
            returncode=0,
            duration_seconds=0.1,
            truncated=False,
            engagement_id=kwargs.get("engagement_id", ""),
            phase=kwargs.get("phase", ""),
            call_id="qa-call-id",
            run_id="",
            output_ref=None,
            stdout_bytes_full=len(out.encode("utf-8")),
            stderr_bytes_full=0,
        )

    monkeypatch.setattr(srv._exe.__class__, "run", fake_run)


@pytest.fixture
def osint_engagement(tmp_paths) -> Engagement:
    """Engagement with both infra and identity scope + OSINT auth ref.

    Relies on ``tmp_paths`` (conftest) to rebind module-level stores
    in osint/parrot/blueteam servers to per-test tmp paths.
    """
    create = EngagementCreate(
        name="E2E OSINT",
        client="self",
        tester="qa",
        authorization_ref="ROE-INFRA-1",
        osint_authorization_ref="ROE-OSINT-1",
        scope_usernames=["octocat"],
        scope_emails=["alice@example.com"],
        scope_domains=["example.com"],
    )
    eng = Engagement(**create.model_dump())

    async def _setup():
        from mcp_servers import parrot_server as ps
        await ps.store.init()
        await ps.store.create_engagement(eng)

    asyncio.run(_setup())
    return eng


# ── Phase A1 + B1: parrot routes osint correctly ─────────────────────────


def test_parrot_tool_run_routes_osint_to_identity_scope(osint_engagement, monkeypatch):
    from mcp_servers.parrot_server import parrot_tool_run

    # Skip the binary check so this passes even without `sherlock` on PATH.
    monkeypatch.setenv("SAP_OSINT_SKIP_BINARY_CHECK", "1")
    # Force binary_available() positive for the parrot pre-flight check.
    monkeypatch.setattr(
        "mcp_servers.parrot_server.binary_available", lambda *_: True
    )
    _patch_parrot_exe(monkeypatch)

    res = asyncio.run(parrot_tool_run(
        name="sherlock_run",
        engagement_id=osint_engagement.id,
        args_json=json.dumps({"username": "octocat"}),
        phase="reconnaissance",
    ))
    assert "error" not in res, res
    # Response shape comes from build_tool_response
    assert res.get("returncode") == 0
    body = res.get("stdout") or res.get("stdout_head") or res.get("body") or ""
    assert "GitHub" in body


def test_parrot_tool_run_osint_rejects_out_of_scope_username(osint_engagement, monkeypatch):
    from mcp_servers.parrot_server import parrot_tool_run

    monkeypatch.setenv("SAP_OSINT_SKIP_BINARY_CHECK", "1")
    monkeypatch.setattr(
        "mcp_servers.parrot_server.binary_available", lambda *_: True
    )
    _patch_parrot_exe(monkeypatch)

    res = asyncio.run(parrot_tool_run(
        name="sherlock_run",
        engagement_id=osint_engagement.id,
        args_json=json.dumps({"username": "not-in-scope"}),
        phase="reconnaissance",
    ))
    assert "error" in res
    assert "scope" in res["error"].lower()


def test_parrot_tool_run_osint_requires_authorization(tmp_paths, monkeypatch):
    """Engagement with identity scope but no osint_authorization_ref → blocked."""
    from mcp_servers.parrot_server import parrot_tool_run

    create = EngagementCreate(
        name="no-auth",
        client="self",
        scope_usernames=["octocat"],
        # no osint_authorization_ref
    )
    eng = Engagement(**create.model_dump())

    async def _setup():
        from mcp_servers import parrot_server as ps
        await ps.store.init()
        await ps.store.create_engagement(eng)

    asyncio.run(_setup())

    monkeypatch.setenv("SAP_OSINT_SKIP_BINARY_CHECK", "1")
    monkeypatch.setattr(
        "mcp_servers.parrot_server.binary_available", lambda *_: True
    )

    res = asyncio.run(parrot_tool_run(
        name="sherlock_run",
        engagement_id=eng.id,
        args_json=json.dumps({"username": "octocat"}),
    ))
    assert "error" in res
    assert "osint_authorization_ref" in res["error"].lower() or "osint authorization" in res["error"].lower()


def test_parrot_tool_run_missing_binary_returns_setup_required(osint_engagement, monkeypatch):
    from mcp_servers.parrot_server import parrot_tool_run

    monkeypatch.setattr(
        "mcp_servers.parrot_server.binary_available", lambda *_: False
    )
    res = asyncio.run(parrot_tool_run(
        name="sherlock_run",
        engagement_id=osint_engagement.id,
        args_json=json.dumps({"username": "octocat"}),
    ))
    assert res.get("error") == "setup_required"
    assert "missing_binary" in res
    assert "install_cmd" in res


# ── parrot_list_tools(available_only) default ────────────────────────────


def test_parrot_list_tools_default_filters_missing(monkeypatch):
    from mcp_servers.parrot_server import parrot_list_tools

    # Pretend everything is missing.
    monkeypatch.setattr(
        "mcp_servers.parrot_server.binary_available", lambda *_: False
    )
    res = asyncio.run(parrot_list_tools(category="osint"))
    assert res["available_only"] is True
    assert res["count"] == 0
    # Opt-out → catalogue visible regardless.
    res2 = asyncio.run(parrot_list_tools(category="osint", available_only=False))
    assert res2["count"] > 0


# ── Phase C3: report autopilot writes to REPORTS_DIR ─────────────────────


def test_generate_assessment_report_writes_file(osint_engagement, tmp_paths, monkeypatch):
    """Direct call to the blueteam tool persists to REPORTS_DIR."""
    monkeypatch.setenv("REPORTS_DIR", str(tmp_paths["reports"]))

    from mcp_servers.blueteam_server import generate_assessment_report

    res = asyncio.run(generate_assessment_report(
        engagement_id=osint_engagement.id, format_type="markdown",
    ))
    assert "saved_to" in res, res
    saved = Path(res["saved_to"])
    assert saved.exists()
    assert saved.parent == tmp_paths["reports"]
    text = saved.read_text(encoding="utf-8")
    assert osint_engagement.client in text or "Security Assessment Report" in text


def test_orchestrator_autoreport_on_phase_reporting(osint_engagement, tmp_paths, monkeypatch):
    """The orchestrator's `_maybe_autoreport` calls the tool when set_phase('reporting')."""
    monkeypatch.setenv("REPORTS_DIR", str(tmp_paths["reports"]))

    # Build a minimal stub orchestrator so we can call the hook in isolation.
    from agent.orchestrator import Orchestrator

    captured: list[tuple[str, dict]] = []

    class _StubRegistry:
        async def call(self, name, args):
            captured.append((name, args))
            if name == "generate_assessment_report":
                # Mimic the real tool's side effect: write a file.
                from mcp_servers.blueteam_server import generate_assessment_report
                return await generate_assessment_report(**args)
            return "{}"

        def is_builtin(self, _name):
            return False

    orch = Orchestrator.__new__(Orchestrator)
    orch._registry = _StubRegistry()
    orch._engagement_id = osint_engagement.id
    orch._on_message = lambda *_a, **_k: None
    orch._truncate_for_callback = lambda s: s if isinstance(s, str) else str(s)

    asyncio.run(orch._maybe_autoreport(
        "set_phase", {"engagement_id": osint_engagement.id, "phase": "reporting"},
    ))
    assert any(name == "generate_assessment_report" for name, _ in captured)
    files = list(tmp_paths["reports"].glob(f"{osint_engagement.id}_*.md"))
    assert files, "auto-report did not produce a file on disk"

    # Idempotent: a second trigger within the same run is a no-op.
    captured.clear()
    asyncio.run(orch._maybe_autoreport(
        "set_phase", {"engagement_id": osint_engagement.id, "phase": "reporting"},
    ))
    assert captured == []


# ── D3: warn when authorization_ref equals osint_authorization_ref ───────


def test_engagement_warns_on_shared_authorization_ref(capsys):
    create = EngagementCreate(
        name="dual",
        client="c",
        authorization_ref="ROE-1",
        osint_authorization_ref="ROE-1",
    )
    Engagement(**create.model_dump())
    err = capsys.readouterr().err
    assert "warning" in err.lower()
    assert "osint" in err.lower()
