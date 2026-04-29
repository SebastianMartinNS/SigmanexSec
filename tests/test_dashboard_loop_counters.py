"""Phase 8.1 — dashboard /api/audit/loop-counters endpoint."""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi.testclient import TestClient


def _seed_audit(audit_path: Path, entries: list[dict]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_loop_counters_aggregates_repetition_blocked(tmp_path, monkeypatch):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setenv("AUDIT_LOG_PATH", str(audit))
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")

    _seed_audit(audit, [
        {"engagement_id": "E1", "actor": "agent",
         "action": "tool_complete", "target": "nmap", "details": {}},
        {"engagement_id": "E1", "actor": "agent",
         "action": "decision.repetition_blocked", "target": "sherlock_run",
         "details": {"run_id": "R1", "tool": "sherlock_run"}},
        {"engagement_id": "E1", "actor": "agent",
         "action": "decision.repetition_blocked", "target": "sherlock_run",
         "details": {"run_id": "R1", "tool": "sherlock_run"}},
        {"engagement_id": "E2", "actor": "agent",
         "action": "decision.repetition_blocked", "target": "holehe_run",
         "details": {"run_id": "R2", "tool": "holehe_run"}},
    ])

    from sap_dashboard.backend.app import app
    client = TestClient(app)

    r = client.get("/api/audit/loop-counters", auth=("u", "p"))
    assert r.status_code == 200
    body = r.json()
    assert body["tool_call_loop_detected"] == 3
    assert body["by_engagement"] == {"E1": 2, "E2": 1}
    assert body["by_run"] == {"R1": 2, "R2": 1}
    assert body["by_tool"] == {"sherlock_run": 2, "holehe_run": 1}
    assert len(body["recent"]) == 3

    # Filter by engagement.
    r = client.get("/api/audit/loop-counters?engagement_id=E2", auth=("u", "p"))
    assert r.status_code == 200
    body = r.json()
    assert body["tool_call_loop_detected"] == 1
    assert body["by_tool"] == {"holehe_run": 1}

    # Filter by run.
    r = client.get("/api/audit/loop-counters?run_id=R1", auth=("u", "p"))
    assert r.status_code == 200
    assert r.json()["tool_call_loop_detected"] == 2


def test_loop_counters_empty_when_no_audit_log(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "missing.jsonl"))
    monkeypatch.setenv("SAP_DASHBOARD_USER", "u")
    monkeypatch.setenv("SAP_DASHBOARD_PASS", "p")
    monkeypatch.setenv("SAP_DISABLE_STORAGE_GC", "1")

    from sap_dashboard.backend.app import app
    client = TestClient(app)
    r = client.get("/api/audit/loop-counters", auth=("u", "p"))
    assert r.status_code == 200
    assert r.json()["tool_call_loop_detected"] == 0
