"""Phase 6: dashboard outputs route + CLI + storage GC scheduler."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

# ── Helpers ─────────────────────────────────────────────────────────────────

@pytest.fixture
def populated_store(tmp_paths, monkeypatch):
    """Create a ToolOutputStore with one persisted call."""
    from core.tool_output_store import (
        get_tool_output_store,
        reset_tool_output_store,
    )
    reset_tool_output_store()
    store = get_tool_output_store()

    async def _populate():
        ref = await store.store(
            run_id="run_test",
            tool="nmap",
            command_redacted="nmap -sV 10.0.0.1",
            stdout=b"hello stdout payload",
            stderr=b"warn",
            returncode=0,
            duration_seconds=0.5,
            engagement_id="eng_test",
            target="10.0.0.1",
            phase="recon",
        )
        # drop a fake artifact
        adir = Path(ref.artifacts_dir)
        adir.mkdir(parents=True, exist_ok=True)
        (adir / "nmap.xml").write_text("<nmap/>")
        return ref

    ref = asyncio.run(_populate())
    yield store, ref
    reset_tool_output_store()


# ── Dashboard route tests ───────────────────────────────────────────────────

def test_outputs_route_list_and_get(populated_store, monkeypatch):
    store, ref = populated_store
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    from sap_dashboard.backend.app import app
    client = TestClient(app)

    auth = ("u", "p")
    r = client.get(f"/api/runs/{ref.run_id}/outputs", auth=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] >= 1
    assert any(it["call_id"] == ref.call_id for it in data["items"])

    r = client.get(f"/api/outputs/{ref.call_id}", auth=auth)
    assert r.status_code == 200
    assert r.json()["call_id"] == ref.call_id

    r = client.get(f"/api/outputs/{ref.call_id}/stdout", auth=auth)
    assert r.status_code == 200
    assert "hello stdout payload" in r.text

    r = client.get(f"/api/outputs/{ref.call_id}/stdout?head=5", auth=auth)
    assert r.status_code == 200
    assert r.text == "hello"

    r = client.get(f"/api/outputs/{ref.call_id}/artifacts", auth=auth)
    assert r.status_code == 200
    assert any(f["name"] == "nmap.xml" for f in r.json()["files"])

    r = client.get(f"/api/outputs/{ref.call_id}/artifacts/nmap.xml", auth=auth)
    assert r.status_code == 200
    assert r.text == "<nmap/>"


def test_outputs_route_path_traversal_blocked(populated_store, monkeypatch):
    _store, ref = populated_store
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    from sap_dashboard.backend.app import app
    client = TestClient(app)
    r = client.get(
        f"/api/outputs/{ref.call_id}/artifacts/../../../etc/passwd",
        auth=("u", "p"),
    )
    assert r.status_code in (400, 404)


def test_outputs_route_404_unknown_call(monkeypatch, tmp_paths):
    from core.tool_output_store import reset_tool_output_store
    reset_tool_output_store()
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")
    from sap_dashboard.backend.app import app
    client = TestClient(app)
    r = client.get("/api/outputs/call_doesnotexist", auth=("u", "p"))
    assert r.status_code == 404


# ── CLI tests ───────────────────────────────────────────────────────────────

def test_cli_outputs_ls_show_cat(populated_store):
    _store, ref = populated_store
    from cli import cli
    runner = CliRunner()

    r = runner.invoke(cli, ["outputs", "ls", "--run", ref.run_id])
    assert r.exit_code == 0, r.output
    assert ref.call_id in r.output

    r = runner.invoke(cli, ["outputs", "show", ref.call_id])
    assert r.exit_code == 0, r.output
    assert ref.call_id in r.output

    r = runner.invoke(cli, ["outputs", "cat", ref.call_id, "--kind", "stdout"])
    assert r.exit_code == 0, r.output
    assert "hello stdout payload" in r.output


def test_cli_outputs_gc_dry_run(populated_store):
    _store, _ref = populated_store
    from cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["outputs", "gc", "--retention-days", "0", "--dry-run"])
    assert r.exit_code == 0, r.output
    # Dry run reports candidate counts
    assert "candidates" in r.output


# ── GC scheduler smoke test ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_storage_gc_scheduler_runs_once(populated_store):
    from core.storage_gc import start_gc_scheduler
    store, _ref = populated_store
    task = start_gc_scheduler(
        retention_days=10_000, interval_seconds=10, store=store,
    )
    # Let one iteration run, then cancel
    await asyncio.sleep(0.05)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    assert task.cancelled() or task.done()
