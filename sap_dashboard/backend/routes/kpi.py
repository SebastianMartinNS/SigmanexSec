"""
sap_dashboard/backend/routes/kpi.py — Quality-gate metrics endpoint.

Reads ``logs/audit.jsonl`` and the engagement findings, then computes a
small set of KPIs via :func:`core.adaptive.compute_kpi_report`. Used by
the dashboard to surface tool repetition rate, hallucination proxy and
the decision-event histogram.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query

from core.adaptive import compute_kpi_report, iter_audit_rows
from core.session_store import SessionStore

from ..deps import REPO_ROOT, require_auth
from ..rbac import ROLE_VIEWER, require_role

router = APIRouter(
    prefix="/api/kpi",
    tags=["kpi"],
    # KPI dashboards are read-only data; any authenticated viewer can read them.
    dependencies=[Depends(require_role(ROLE_VIEWER))],
)


def _audit_path() -> Path:
    return Path(os.environ.get("AUDIT_LOG_PATH", str(REPO_ROOT / "logs" / "audit.jsonl")))


def _db_path() -> str:
    return os.environ.get(
        "SESSION_DB_PATH", str(REPO_ROOT / "sessions" / "assessments.db")
    )


@router.get("/{engagement_id}")
async def kpi_for_engagement(
    engagement_id: str,
    include_decisions: bool = Query(
        True,
        description="Include the decision-kind histogram in the response",
    ),
    _user: str = Depends(require_auth),
) -> dict:
    """Compute the live KPI snapshot for an engagement."""
    if not engagement_id or not engagement_id.strip():
        raise HTTPException(status_code=400, detail="engagement_id required")

    audit_rows = list(iter_audit_rows(_audit_path(), engagement_id=engagement_id))

    store = SessionStore(_db_path())
    await store.init()
    findings = await store.get_findings(engagement_id)

    report = compute_kpi_report(
        engagement_id=engagement_id,
        audit_rows=audit_rows,
        findings=findings,
    )
    payload = report.to_dict()
    if not include_decisions:
        payload.pop("decision_counts", None)
    # Expose a few derived signals the frontend chart uses directly.
    payload["quality_gate"] = {
        # Phase-6 design KPIs: repetition < 0.30, hallucination_proxy < 0.40 of findings.
        "repetition_ok": payload["tool_repetition_rate"] < 0.30,
        "hallucination_ratio": (
            payload["hallucination_proxy"] / payload["findings_total"]
            if payload["findings_total"] else 0.0
        ),
    }
    payload["quality_gate"]["hallucination_ok"] = (
        payload["quality_gate"]["hallucination_ratio"] < 0.40
    )
    return payload
