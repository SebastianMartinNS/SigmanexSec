"""Tests for the Phase 2 adaptive extension of the Finding model and
the SessionStore migration that backfills the new columns."""
from __future__ import annotations

import sqlite3
from datetime import datetime

import pytest

from core.models import Finding, FindingCategory, Severity
from core.session_store import SessionStore
from core.time_utils import utcnow as _sap_utcnow


def test_finding_defaults_are_backward_compatible():
    f = Finding(
        engagement_id="eng-1",
        severity=Severity.LOW,
        category=FindingCategory.OPEN_PORT,
        title="t",
        description="d",
    )
    assert f.confidence == pytest.approx(0.5)
    assert f.confidence_rationale == ""
    assert f.evidence_audit_ids == []
    assert f.verification_count == 0
    assert isinstance(f.freshness_ts, datetime)


@pytest.mark.asyncio
async def test_session_store_persists_adaptive_columns(tmp_path):
    db = tmp_path / "assessments.db"
    store = SessionStore(str(db))
    await store.init()

    finding = Finding(
        engagement_id="eng-1",
        severity=Severity.HIGH,
        category=FindingCategory.SQLI,
        title="boolean-based blind",
        description="param id is injectable",
        evidence="status differs on 1=1 vs 1=2",
        confidence=0.85,
        confidence_rationale="rc_ok+pattern_match+cve",
        evidence_audit_ids=["a-1", "a-2"],
    )
    await store.add_finding(finding)
    findings = await store.get_findings("eng-1")
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == pytest.approx(0.85)
    assert f.confidence_rationale == "rc_ok+pattern_match+cve"
    assert f.evidence_audit_ids == ["a-1", "a-2"]
    assert f.verification_count == 0


@pytest.mark.asyncio
async def test_session_store_migrates_legacy_findings_table(tmp_path):
    """Legacy DBs (pre-adaptive) must keep working after init()."""
    db = tmp_path / "legacy.db"
    # Build a legacy schema by hand (no adaptive columns).
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE engagements (id TEXT PRIMARY KEY);
        CREATE TABLE findings (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            host_id TEXT,
            severity TEXT,
            category TEXT,
            title TEXT,
            description TEXT,
            evidence TEXT,
            cve TEXT,
            cvss_score REAL,
            tool_used TEXT,
            attack_path TEXT,
            mitre_techniques TEXT,
            remediation TEXT,
            detection_rule TEXT,
            hardening_steps TEXT,
            created_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO findings (id, engagement_id, severity, category, title, "
        "description, mitre_techniques, hardening_steps, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("legacy-1", "eng-1", "low", "open_port", "old", "row", "[]", "[]",
         _sap_utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    store = SessionStore(str(db))
    await store.init()  # must not raise

    findings = await store.get_findings("eng-1")
    assert len(findings) == 1
    legacy = findings[0]
    # Defaults backfilled from the migration.
    assert legacy.confidence == pytest.approx(0.5)
    assert legacy.evidence_audit_ids == []
    assert legacy.verification_count == 0
