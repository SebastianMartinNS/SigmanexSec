"""
core/adaptive/decisions.py — Standardized audit events for agent decisions.

The adaptive layer needs a stable schema for "what did the runner choose
and why?" to support KPI dashboards, regression analysis and offline
evaluation. This module emits AuditEntry rows tagged with `action="decision"`
and a structured `details` payload.

Why a separate helper:
- Centralizes the action namespace (DecisionKind) so dashboards and tests
  can rely on a closed enum.
- Keeps producers (orchestrator, playbook router, repetition handler) free
  of audit-shape boilerplate.
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Optional

from core.audit_log import AuditLog
from core.models import AuditEntry

_log = logging.getLogger(__name__)


class DecisionKind(str, Enum):
    REPETITION_BLOCKED = "decision.repetition_blocked"
    REPETITION_PIVOT = "decision.repetition_pivot"
    SCENARIO_CLASSIFIED = "decision.scenario_classified"
    PLAYBOOK_BRANCH = "decision.playbook_branch"
    FALLBACK_SUGGESTED = "decision.fallback_suggested"
    CONFIDENCE_UPDATED = "decision.confidence_updated"
    DRIFT_DETECTED = "decision.drift_detected"
    OPERATOR_FEEDBACK = "decision.operator_feedback"


async def emit_decision(
    audit: Optional[AuditLog],
    *,
    engagement_id: str,
    kind: DecisionKind,
    summary: str,
    details: Optional[dict[str, Any]] = None,
    target: str = "",
    actor: str = "agent",
) -> None:
    """Best-effort write of a decision audit entry.

    The function never raises: audit pressure must not break the runner.
    """
    if audit is None:
        return
    payload: dict[str, Any] = {"summary": summary}
    if details:
        payload.update(details)
    try:
        await audit.write(AuditEntry(
            engagement_id=engagement_id,
            actor=actor,
            action=kind.value,
            target=target,
            details=payload,
        ))
    except Exception as exc:  # pragma: no cover - defensive
        _log.warning("decision audit emit failed (%s): %s", kind.value, exc)
