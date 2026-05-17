"""Tests for executor persistence — verify ToolOutputStore wiring."""
from __future__ import annotations

import pytest

from core.executor import ToolExecutor
from core.tool_output_store import ToolOutputStore, reset_tool_output_store


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_tool_output_store()
    yield
    reset_tool_output_store()


@pytest.mark.asyncio
async def test_executor_persists_full_output(tmp_paths, monkeypatch):
    monkeypatch.setenv("SAP_RUN_ID", "run_persist1")
    # Force allowlist permissive: use a fake binary via /usr/bin/env
    # Actually the executor calls _check_tool against allowlist; use 'echo'
    # which is normally NOT on the list. We monkeypatch _allowed_tools.
    from core import executor as _ex
    monkeypatch.setattr(_ex, "_allowed_tools", lambda: {"printf"})
    monkeypatch.setattr(_ex, "_blocked_patterns", lambda: [])
    monkeypatch.setattr(_ex, "_persist_outputs", lambda: True)

    payload = "X" * 5000  # below default cap
    exe = ToolExecutor(run_id="run_persist1")
    result = await exe.run("printf", ["%s", payload], engagement_id="eng_a")

    assert result.returncode == 0
    assert result.call_id and result.call_id.startswith("call_")
    assert result.run_id == "run_persist1"
    assert result.output_ref is not None
    assert result.output_ref.stdout_uri.startswith(
        f"sap://run/run_persist1/output/{result.call_id}/stdout"
    )
    assert result.stdout_bytes_full == len(payload.encode())
    assert result.truncated is False

    # Read back through the store
    store = ToolOutputStore(
        db_path=str(tmp_paths["sessions"] / "assessments.db"),
        sessions_root=tmp_paths["sessions"],
    )
    data = await store.read(result.call_id)
    assert data == payload.encode()


@pytest.mark.asyncio
async def test_executor_caps_in_memory_but_persists_full(tmp_paths, monkeypatch):
    monkeypatch.setenv("SAP_RUN_ID", "run_cap")
    from core import executor as _ex
    monkeypatch.setattr(_ex, "_allowed_tools", lambda: {"printf"})
    monkeypatch.setattr(_ex, "_blocked_patterns", lambda: [])
    monkeypatch.setattr(_ex, "_max_output", lambda: 100)        # tiny in-memory cap
    monkeypatch.setattr(_ex, "_stderr_max_output", lambda: 100)
    monkeypatch.setattr(_ex, "_persist_outputs", lambda: True)

    payload = "Z" * 4000
    exe = ToolExecutor(run_id="run_cap")
    result = await exe.run("printf", ["%s", payload], engagement_id="eng_a")

    assert result.truncated is True
    assert len(result.stdout) == 100
    assert result.stdout_bytes_full == 4000  # full size preserved on disk

    store = ToolOutputStore(
        db_path=str(tmp_paths["sessions"] / "assessments.db"),
        sessions_root=tmp_paths["sessions"],
    )
    data = await store.read(result.call_id)
    assert data == payload.encode()  # disk has the full thing


@pytest.mark.asyncio
async def test_executor_no_persist_when_disabled(tmp_paths, monkeypatch):
    monkeypatch.setenv("SAP_RUN_ID", "run_off")
    from core import executor as _ex
    monkeypatch.setattr(_ex, "_allowed_tools", lambda: {"printf"})
    monkeypatch.setattr(_ex, "_blocked_patterns", lambda: [])
    monkeypatch.setattr(_ex, "_persist_outputs", lambda: False)

    exe = ToolExecutor(run_id="run_off")
    result = await exe.run("printf", ["%s", "hi"], engagement_id="eng")

    assert result.output_ref is None
    # call_id is still allocated (used as audit correlation key)
    assert result.call_id.startswith("call_")


@pytest.mark.asyncio
async def test_executor_no_persist_when_run_id_empty(tmp_paths, monkeypatch):
    """Contract pin: an executor with empty run_id MUST NOT persist outputs.

    The MCP servers historically constructed ToolExecutor() with no run_id;
    this test guards against accidental regressions of that path. When the
    orchestrator wants persistence on it must call ``set_run_id()`` (or
    ``set_run_context_*`` MCP tool) explicitly.
    """
    # Make sure the env doesn't accidentally inject a run_id.
    monkeypatch.delenv("SAP_RUN_ID", raising=False)
    from core import executor as _ex
    monkeypatch.setattr(_ex, "_allowed_tools", lambda: {"printf"})
    monkeypatch.setattr(_ex, "_blocked_patterns", lambda: [])
    monkeypatch.setattr(_ex, "_persist_outputs", lambda: True)

    exe = ToolExecutor()
    assert exe._run_id == ""
    result = await exe.run("printf", ["%s", "noop"], engagement_id="eng")
    # Persistence enabled by config but skipped because run_id is missing.
    assert result.output_ref is None
    assert result.run_id == ""


@pytest.mark.asyncio
async def test_executor_set_run_id_reenables_persistence(tmp_paths, monkeypatch):
    """``set_run_id`` rebinds the executor to a real run; subsequent runs persist."""
    monkeypatch.delenv("SAP_RUN_ID", raising=False)
    from core import executor as _ex
    monkeypatch.setattr(_ex, "_allowed_tools", lambda: {"printf"})
    monkeypatch.setattr(_ex, "_blocked_patterns", lambda: [])
    monkeypatch.setattr(_ex, "_persist_outputs", lambda: True)

    exe = ToolExecutor()
    # Before binding: no persistence.
    r1 = await exe.run("printf", ["%s", "before"], engagement_id="eng")
    assert r1.output_ref is None

    exe.set_run_id("run_rebound")
    r2 = await exe.run("printf", ["%s", "after"], engagement_id="eng")
    assert r2.run_id == "run_rebound"
    assert r2.output_ref is not None
    assert r2.output_ref.stdout_uri.startswith(
        f"sap://run/run_rebound/output/{r2.call_id}/stdout"
    )
