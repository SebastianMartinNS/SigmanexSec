"""
P2.2 — GDPR purge + retention.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.audit_log import AuditLog, verify_audit_chain
from core.gdpr import apply_retention, purge_engagement
from core.models import AuditEntry, Engagement, EngagementStatus, Phase
from core.session_store import SessionStore


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SAP_SESSIONS_DIR",  str(tmp_path / "sessions"))
    monkeypatch.setenv("SAP_LOGS_DIR",      str(tmp_path / "logs"))
    monkeypatch.setenv("SAP_REPORTS_DIR",   str(tmp_path / "reports"))
    monkeypatch.setenv("SESSION_DB_PATH",   str(tmp_path / "sessions" / "assessments.db"))
    monkeypatch.setenv("AUDIT_LOG_PATH",    str(tmp_path / "logs" / "audit.jsonl"))
    Path(tmp_path / "sessions").mkdir(parents=True, exist_ok=True)
    Path(tmp_path / "logs").mkdir(parents=True, exist_ok=True)
    Path(tmp_path / "reports").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.mark.asyncio
async def test_purge_engagement_removes_records_and_audit_lines(env):
    db_path = str(env / "sessions" / "assessments.db")
    audit_path = str(env / "logs" / "audit.jsonl")
    reports_path = str(env / "reports")

    # Seed: two engagements, a finding only on E1, audit lines for both.
    store = SessionStore(db_path)
    await store.init()
    e1 = Engagement(id="E1", name="t1", client="acme", scope=["10.0.0.0/24"],
                    status=EngagementStatus.ACTIVE, phase=Phase.RECON)
    e2 = Engagement(id="E2", name="t2", client="acme", scope=["10.0.0.0/24"],
                    status=EngagementStatus.ACTIVE, phase=Phase.RECON)
    await store.create_engagement(e1)
    await store.create_engagement(e2)

    log = AuditLog(audit_path)
    await log.write(AuditEntry(engagement_id="E1", actor="t", action="alpha"))
    await log.write(AuditEntry(engagement_id="E2", actor="t", action="beta"))
    await log.write(AuditEntry(engagement_id="E1", actor="t", action="gamma"))
    await log.flush()
    await log.close()

    # Drop a fake report file for E1.
    Path(reports_path, "E1_20260101_120000.md").write_text("# secret report")
    Path(reports_path, "E2_20260101_120000.md").write_text("# other")

    res = await purge_engagement("E1", db_path=db_path,
                                 audit_path=audit_path,
                                 reports_path=reports_path)

    # E1 is gone from the DB; E2 survives.
    store2 = SessionStore(db_path)
    await store2.init()
    survivors = await store2.list_engagements()
    assert {e.id for e in survivors} == {"E2"}
    assert res.deleted_engagement is True
    assert res.deleted_audit_lines == 2  # E1 had 2 entries
    assert res.deleted_report_files == 1
    assert not Path(reports_path, "E1_20260101_120000.md").exists()
    assert     Path(reports_path, "E2_20260101_120000.md").exists()


@pytest.mark.asyncio
async def test_purge_preserves_audit_chain_integrity(env):
    audit_path = str(env / "logs" / "audit.jsonl")
    log = AuditLog(audit_path)
    for eid, action in [("A", "x"), ("B", "y"), ("A", "z"), ("C", "w"), ("A", "q")]:
        await log.write(AuditEntry(engagement_id=eid, actor="t", action=action))
    await log.flush()
    await log.close()

    res = await purge_engagement(
        "A",
        db_path=str(env / "sessions" / "assessments.db"),
        audit_path=audit_path,
    )
    assert res.deleted_audit_lines == 3
    ok, n, msg = verify_audit_chain(audit_path)
    assert ok, f"chain broken after purge: {msg} at line {n}"
    # Two original survivors + one new "gdpr_purge" line.
    lines = Path(audit_path).read_text().strip().splitlines()
    assert len(lines) == 3
    actions = [json.loads(L)["action"] for L in lines]
    assert actions[-1] == "gdpr_purge"


@pytest.mark.asyncio
async def test_retention_drops_old_entries_and_keeps_chain(env, monkeypatch):
    audit_path = str(env / "logs" / "audit.jsonl")

    log = AuditLog(audit_path)
    # Force an old timestamp for the first entry, fresh for the second.
    old_ts = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    fresh = AuditEntry(engagement_id="E", actor="t", action="fresh")
    old   = AuditEntry(engagement_id="E", actor="t", action="old")
    # Override timestamp post-construction (Pydantic allows reassignment by default).
    old.timestamp = datetime.fromisoformat(old_ts)
    await log.write(old)
    await log.write(fresh)
    await log.flush()
    await log.close()

    res = await apply_retention(
        audit_max_age_days=180,
        tool_output_max_age_days=0,
        audit_path=audit_path,
    )
    assert res.audit_lines_removed == 1
    ok, n, msg = verify_audit_chain(audit_path)
    assert ok, msg


@pytest.mark.asyncio
async def test_purge_rejects_unsafe_engagement_id(env):
    with pytest.raises(ValueError):
        await purge_engagement("../etc/passwd")
    with pytest.raises(ValueError):
        await purge_engagement("foo/bar")
    with pytest.raises(ValueError):
        await purge_engagement("")
