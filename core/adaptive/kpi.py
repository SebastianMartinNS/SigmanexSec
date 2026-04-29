"""
core/adaptive/kpi.py — Quality-gate metrics computed from audit JSONL.

The dashboard surfaces a small set of KPIs derived from the audit log so
operators can tell whether the adaptive layer is actually moving the
needle:

- ``tool_repetition_rate`` — fraction of executed tool calls that hit
  the circuit-breaker (``decision.repetition_blocked``). Lower = better.
- ``pivot_rate`` — fraction of repetition events that produced an
  alternative tool suggestion (``decision.repetition_pivot``). Higher
  is better when repetition_rate is non-zero.
- ``hallucination_proxy`` — count of findings with ``confidence > 0.7``
  but **no** ``evidence_audit_ids``. The signal is intentionally
  conservative: it only flags claims the agent itself rated high while
  failing to attach provenance.
- ``confidence_distribution`` — bucketed histogram (0.0–0.4, 0.4–0.7,
  0.7–1.0) of finding confidence values for one engagement.
- ``decision_counts`` — histogram of ``DecisionKind`` events.
- ``drift_rate`` — fraction of verifications whose delta exceeded the
  drift threshold.

The functions are pure: they take parsed JSONL rows and a finding list.
The route layer is responsible for I/O. This makes the rules trivially
testable and lets us compute KPIs over a simulated audit stream too.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from core.adaptive.decisions import DecisionKind
from core.models import Finding


# All decision-kind values, useful for histogram pre-seeding.
_DECISION_VALUES: tuple[str, ...] = tuple(k.value for k in DecisionKind)


@dataclass
class KPIReport:
    engagement_id: str
    total_tool_calls: int = 0
    repetition_blocked: int = 0
    repetition_pivots: int = 0
    tool_repetition_rate: float = 0.0  # repetition_blocked / max(total, 1)
    pivot_rate: float = 0.0            # pivots / max(repetition_blocked, 1)
    decision_counts: dict[str, int] = field(default_factory=dict)
    confidence_distribution: dict[str, int] = field(
        default_factory=lambda: {"low": 0, "medium": 0, "high": 0}
    )
    hallucination_proxy: int = 0
    drift_events: int = 0
    drift_rate: float = 0.0  # drift_events / max(verifications, 1)
    verifications: int = 0
    operator_feedback_events: int = 0
    findings_total: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


def _is_tool_call(action: str) -> bool:
    """Heuristic: an audit row counts as a real tool call when it carries
    one of the standard tool-execution actions emitted by the executor /
    MCP wrappers. ``decision.*`` rows are excluded by design."""
    if not action:
        return False
    if action.startswith("decision."):
        return False
    return action in {
        "tool_executed",
        "tool_call",
        "mcp_tool_call",
        "command_executed",
    }


def iter_audit_rows(
    path: Path, *, engagement_id: Optional[str] = None
) -> Iterable[dict]:
    """Yield decoded JSONL rows from ``path``. Silently skips bad lines."""
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if engagement_id and row.get("engagement_id") != engagement_id:
                continue
            yield row


def _bucket_confidence(value: float) -> str:
    if value < 0.4:
        return "low"
    if value < 0.7:
        return "medium"
    return "high"


def compute_kpi_report(
    *,
    engagement_id: str,
    audit_rows: Iterable[dict],
    findings: Iterable[Finding],
) -> KPIReport:
    """Build a :class:`KPIReport` from raw audit rows and findings.

    ``audit_rows`` may be a generator — we only iterate it once.
    """
    rep = KPIReport(engagement_id=engagement_id)
    rep.decision_counts = {v: 0 for v in _DECISION_VALUES}

    for row in audit_rows:
        if engagement_id and row.get("engagement_id") != engagement_id:
            continue
        action = str(row.get("action") or "")
        if _is_tool_call(action):
            rep.total_tool_calls += 1
            continue
        if not action.startswith("decision."):
            continue
        rep.decision_counts[action] = rep.decision_counts.get(action, 0) + 1
        if action == DecisionKind.REPETITION_BLOCKED.value:
            rep.repetition_blocked += 1
        elif action == DecisionKind.REPETITION_PIVOT.value:
            rep.repetition_pivots += 1
        elif action in (
            DecisionKind.CONFIDENCE_UPDATED.value,
            DecisionKind.DRIFT_DETECTED.value,
        ):
            rep.verifications += 1
            if action == DecisionKind.DRIFT_DETECTED.value:
                rep.drift_events += 1
        elif action == DecisionKind.OPERATOR_FEEDBACK.value:
            rep.operator_feedback_events += 1

    findings_list = list(findings)
    rep.findings_total = len(findings_list)
    for f in findings_list:
        bucket = _bucket_confidence(float(f.confidence))
        rep.confidence_distribution[bucket] += 1
        if float(f.confidence) > 0.7 and not f.evidence_audit_ids:
            rep.hallucination_proxy += 1

    # Derived rates (defensive division-by-zero handling).
    if rep.total_tool_calls > 0:
        # repetition_blocked counts events, not retries. Cap at 1.0 so the
        # dashboard never shows >100%.
        rep.tool_repetition_rate = min(
            1.0, rep.repetition_blocked / rep.total_tool_calls
        )
    if rep.repetition_blocked > 0:
        rep.pivot_rate = min(
            1.0, rep.repetition_pivots / rep.repetition_blocked
        )
    if rep.verifications > 0:
        rep.drift_rate = rep.drift_events / rep.verifications

    return rep


def compute_kpi_from_path(
    *,
    engagement_id: str,
    audit_path: Path,
    findings: Iterable[Finding],
) -> KPIReport:
    """Convenience wrapper: read JSONL from disk then compute the report."""
    rows = iter_audit_rows(audit_path, engagement_id=engagement_id)
    return compute_kpi_report(
        engagement_id=engagement_id,
        audit_rows=rows,
        findings=findings,
    )
